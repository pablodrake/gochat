package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/pablodrake/gochat/gochatcrypto"
)

type Client struct {
	conn        net.Conn
	publicKey   *rsa.PublicKey
	publicKeyID string
}

type Server struct {
	clients           map[string]*Client
	mu                sync.RWMutex
	heartbeatInterval time.Duration
	sharedKey         []byte
	listener          net.Listener
	shutdownChan      chan struct{}
	wg                sync.WaitGroup
}

func NewServer(heartbeatInterval time.Duration) *Server {
	serverKey, err := gochatcrypto.GenerateAESKey()
	if err != nil {
		log.Fatalf("Failed to generate server key: %v\n", err)
	}
	return &Server{
		clients:           make(map[string]*Client),
		heartbeatInterval: heartbeatInterval,
		sharedKey:         serverKey,
		shutdownChan:      make(chan struct{}),
	}
}

func (s *Server) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Println("Listener closed or error occurred. Stopping to accept new connections:", err)
			return // Exit the loop on accept error
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	s.wg.Add(1)
	defer s.wg.Done()
	defer conn.Close()
	reader := bufio.NewReader(conn)

	publicKey, err := s.readPublicKey(reader)
	if err != nil {
		log.Println("Failed to read public key:", err)
		return
	}

	publicKeyID := gochatcrypto.PublicKeyIdentifier(publicKey)

	err = s.sendEncryptedSharedKey(conn, publicKey)
	if err != nil {
		log.Printf("Failed to send encrypted shared key to %s: %v\n", publicKeyID, err)
		return
	}

	client := &Client{conn: conn, publicKey: publicKey, publicKeyID: publicKeyID}
	s.addClient(client)
	defer s.removeClient(client)

	for {
		select {
		case <-s.shutdownChan:
			log.Printf("Server is shutting down. Closing connection to %s\n", publicKeyID)
			return
		default:
			// Set a deadline to avoid blocking indefinitely
			conn.SetReadDeadline(time.Now().Add(s.heartbeatInterval))
			message, err := s.readMessage(conn)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Read timeout, continue to next iteration
				}
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("Error reading from %s: %v\n", publicKeyID, err)
				}
				return
			}
			if message == "" {
				continue
			} else if message == "heartbeat" {
				err = s.sendAESEncryptedMessage(conn, []byte("heartbeat ack"))
				if err != nil {
					log.Printf("Failed to send heartbeat ack to %s: %v\n", publicKeyID, err)
					return
				}
			} else {
				s.broadcastMessage(message, client)
			}
		}
	}
}

func (s *Server) readMessage(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	encryptedMessage, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	encryptedMessage = strings.TrimSpace(encryptedMessage)
	if encryptedMessage == "heartbeat" {
		return encryptedMessage, nil
	}

	decodedMessage, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", fmt.Errorf("error decoding message: %v", err)
	}

	decryptedMessage, err := gochatcrypto.DecryptWithAES(s.sharedKey, decodedMessage)
	if err != nil {
		return "", fmt.Errorf("error decrypting message: %v", err)
	}

	return string(decryptedMessage), nil
}

func (s *Server) sendAESEncryptedMessage(conn net.Conn, message []byte) error {
	encryptedMessage, err := gochatcrypto.EncryptWithAES(s.sharedKey, message)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %v", err)
	}

	encodedMessage := base64.StdEncoding.EncodeToString(encryptedMessage) + "\n"
	_, err = conn.Write([]byte(encodedMessage))
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	return nil
}

func (s *Server) broadcastMessage(message string, sender *Client) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, client := range s.clients {
		if client != sender {
			err := s.sendAESEncryptedMessage(client.conn, []byte(message))
			if err != nil {
				log.Printf("Error sending message to %s: %v\n", client.publicKeyID, err)
			}
		}
	}
}

func (s *Server) shutdown() {
	log.Println("Shutdown signal received. Initiating graceful shutdown...")

	// Close the listener to stop accepting new connections
	s.listener.Close()

	// Close the shutdown channel to signal other goroutines
	close(s.shutdownChan)

	// Lock the clients map while accessing it
	s.mu.Lock()

	// Send shutdown message to all clients
	for _, client := range s.clients {
		err := s.sendAESEncryptedMessage(client.conn, []byte("Server is shutting down. Goodbye!"))
		if err != nil {
			log.Printf("Error sending shutdown message to %s: %v\n", client.publicKeyID, err)
		}
	}
	s.mu.Unlock()

	// Wait briefly to allow clients to receive the message
	time.Sleep(2 * time.Second)

	// Now force close any remaining connections
	s.forceCloseRemainingConnections()

	log.Println("Server has shut down.")
}

func (s *Server) forceCloseRemainingConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, client := range s.clients {
		client.conn.Close()
	}
	s.clients = make(map[string]*Client)
}

func (s *Server) addClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.publicKeyID] = client
	log.Printf("Client connected: %s\n", client.publicKeyID)
}

func (s *Server) removeClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.publicKeyID]; exists {
		delete(s.clients, client.publicKeyID)
		log.Printf("Client disconnected: %s\n", client.publicKeyID)
	}
}

func (s *Server) readPublicKey(reader *bufio.Reader) (*rsa.PublicKey, error) {
	var publicKeyPEM string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read public key: %w", err)
		}
		publicKeyPEM += line
		if strings.TrimSpace(line) == "-----END RSA PUBLIC KEY-----" {
			break
		}
	}
	return gochatcrypto.ParseRSAPublicKey(publicKeyPEM)
}

func (s *Server) sendEncryptedSharedKey(conn net.Conn, publicKey *rsa.PublicKey) error {
	encryptedSharedKey, err := gochatcrypto.EncryptWithRSA(publicKey, s.sharedKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt shared key: %v", err)
	}

	encodedSharedKey := base64.StdEncoding.EncodeToString(encryptedSharedKey) + "\n"
	_, err = conn.Write([]byte(encodedSharedKey))
	if err != nil {
		return fmt.Errorf("failed to send encrypted shared key: %v", err)
	}

	return nil
}

func main() {
	var debug = true
	if debug {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.Discard)
	}

	server := NewServer(200 * time.Second)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	t, err := tor.Start(context.TODO(), nil)
	if err != nil {
		log.Fatal("Failed to start Tor:", err)
	}
	defer t.Close()

	onion, err := t.Listen(context.Background(), &tor.ListenConf{RemotePorts: []int{9999}, Version3: true})
	if err != nil {
		log.Fatal("Failed to create onion service:", err)
	}
	server.listener = onion

	log.Printf("Server started. Connect with: %v.onion:9999\n", onion.ID)

	go server.acceptConnections()

	// Wait for shutdown signal
	<-sigChan
	server.shutdown()
}
