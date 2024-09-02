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
}

func main() {
	debug := true
	if debug {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.Discard)
	}

	server := NewServer(30 * time.Second)

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
	log.Println("Shutdown signal received. Initiating graceful shutdown...")
	server.shutdown()
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
		select {
		case <-s.shutdownChan:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.shutdownChan:
					return
				default:
					log.Println("Failed to accept connection:", err)
				}
				continue
			}
			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
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
			return
		default:
			conn.SetDeadline(time.Now().Add(s.heartbeatInterval))
			message, err := s.readMessage(conn)
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from %s: %v\n", publicKeyID, err)
				}
				return
			}
			if message == "" {
				log.Printf("Empty message received from %s\n", publicKeyID)
				continue
			} else if message == "heartbeat" {
				log.Printf("Received heartbeat from %s\n", publicKeyID)
				err = s.sendMessage(conn, []byte("heartbeat ack"))
				if err != nil {
					log.Printf("Failed to send heartbeat ack to %s: %v\n", publicKeyID, err)
					return
				}
			} else {
				log.Printf("%s: %s\n", publicKeyID, message)
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

func (s *Server) sendMessage(conn net.Conn, message []byte) error {
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
			err := s.sendMessage(client.conn, []byte(message))
			if err != nil {
				log.Printf("Error sending message to %s: %v\n", client.publicKeyID, err)
			}
		}
	}
}

func (s *Server) shutdown() {
	close(s.shutdownChan)
	s.listener.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	shutdownMessage := "Server is shutting down. Goodbye!"
	for _, client := range s.clients {
		err := s.sendMessage(client.conn, []byte(shutdownMessage))
		if err != nil {
			log.Printf("Error sending shutdown message to %s: %v\n", client.publicKeyID, err)
		}
		client.conn.Close()
	}

	log.Println("All clients notified. Server shutting down.")
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
	delete(s.clients, client.publicKeyID)
	log.Printf("Client disconnected: %s\n", client.publicKeyID)
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

func (s *Server) sendEncryptedSharedKey (conn net.Conn, publicKey *rsa.PublicKey) error {
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