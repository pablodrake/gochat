// main.go
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
	"github.com/pablodrake/gochat/gochatterminal"
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
	terminal          *gochatterminal.Terminal

	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

// NewServer initializes a new Server instance.
func NewServer(heartbeatInterval time.Duration, terminal *gochatterminal.Terminal) *Server {
	serverKey, err := gochatcrypto.GenerateAESKey()
	if err != nil {
		log.Fatalf("Failed to generate server key: %v\n", err)
	}
	return &Server{
		clients:           make(map[string]*Client),
		heartbeatInterval: heartbeatInterval,
		sharedKey:         serverKey,
		terminal:          terminal,
		done:              make(chan struct{}),
	}
}

// Run starts the server's main loop.
func (s *Server) Run() error {
	for {
		// Reset done channel and once variable at the beginning of each iteration
		s.done = make(chan struct{})
		s.once = sync.Once{}

		// Start Tor and create onion service
		t, err := tor.Start(context.TODO(), nil)
		if err != nil {
			s.terminal.PrintMessage(fmt.Sprintf("Failed to start Tor: %v", err))
			retry := askYesNo("Do you want to try starting Tor again? [yes/no]: ", s.terminal)
			if !retry {
				return nil // Normal termination
			}
			continue
		}
		defer t.Close()

		onion, err := t.Listen(context.Background(), &tor.ListenConf{RemotePorts: []int{9999}, Version3: true})
		if err != nil {
			s.terminal.PrintMessage(fmt.Sprintf("Failed to create onion service: %v", err))
			retry := askYesNo("Do you want to try creating the onion service again? [yes/no]: ", s.terminal)
			if !retry {
				return nil // Normal termination
			}
			continue
		}
		s.listener = onion

		s.terminal.PrintMessage("Server started. Connect with: " + onion.ID + ".onion:9999")

		// Create a new context for this server session
		ctx, cancel := context.WithCancel(context.Background())

		// Start accepting connections
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptConnections(ctx)
		}()

		// Start handling input
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleInput(ctx)
		}()

		// Wait for done signal
		<-s.done

		// Cancel the context to signal all goroutines to stop
		cancel()

		// Cleanup: Close the listener here
		s.cleanupServer()

		// Wait for all goroutines to finish
		s.wg.Wait()

		// Prompt for restarting the server
		retry := askYesNo("Do you want to start another server? [yes/no]: ", s.terminal)
		if !retry {
			return nil // Normal termination
		}
	}
}

// acceptConnections accepts incoming connections.
func (s *Server) acceptConnections(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				// Server is shutting down
				return
			default:
				s.terminal.PrintMessage("Listener error: " + err.Error())
				return
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(ctx, conn)
		}()
	}
}

// handleConnection handles a single client connection.
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	publicKey, err := s.readPublicKey(reader)
	if err != nil {
		s.terminal.PrintMessage(fmt.Sprintf("Failed to read public key: %v", err))
		return
	}

	publicKeyID := gochatcrypto.PublicKeyIdentifier(publicKey)

	err = s.sendEncryptedSharedKey(conn, publicKey)
	if err != nil {
		s.terminal.PrintMessage(fmt.Sprintf("Failed to send encrypted shared key to %s: %v", publicKeyID, err))
		return
	}

	client := &Client{conn: conn, publicKey: publicKey, publicKeyID: publicKeyID}
	s.addClient(client)
	defer s.removeClient(client)

	for {
		select {
		case <-ctx.Done():
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
					s.terminal.PrintMessage(fmt.Sprintf("Error reading from %s: %v", publicKeyID, err))
				}
				return
			}
			if message == "" {
				continue
			} else if message == "heartbeat" {
				err = s.sendAESEncryptedMessage(conn, []byte("heartbeat ack"))
				if err != nil {
					s.terminal.PrintMessage(fmt.Sprintf("Failed to send heartbeat ack to %s: %v", publicKeyID, err))
					return
				}
			} else {
				s.broadcastMessage(message, client)
			}
		}
	}
}

// handleInput manages server input and commands.
func (s *Server) handleInput(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			line, err := s.terminal.ReadLine()
			if err != nil {
				if err == io.EOF {
					// Terminal closed
					return
				}
				s.terminal.PrintMessage(fmt.Sprintf("Error reading input: %v", err))
				continue
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			} else if line == "/exit" {
				s.signalDone()
				return
			} else {
				s.broadcastMessage("Server: "+line, nil)
			}
		}
	}
}

// shutdown initiates the server shutdown process.
func (s *Server) Close() {
	s.terminal.Close()
  fmt.Println("Exiting app...")
	s.signalDone()
	s.cleanupServer()

	// Wait briefly to allow clients to receive the message
	time.Sleep(2 * time.Second)

	// Now force close any remaining connections
	s.forceCloseRemainingConnections()
}

// signalDone safely closes the done channel once.
func (s *Server) signalDone() {
	s.once.Do(func() {
		close(s.done)
	})
}

// cleanupServer performs any necessary cleanup during shutdown.
func (s *Server) cleanupServer() {
	// Close the listener to stop accepting new connections
	if s.listener != nil {
		s.listener.Close()
	}
}

// readMessage reads and decrypts messages from clients.
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

// broadcastMessage sends a message to all connected clients.
func (s *Server) broadcastMessage(message string, sender *Client) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, client := range s.clients {
		if client != sender {
			err := s.sendAESEncryptedMessage(client.conn, []byte(message))
			if err != nil {
				s.terminal.PrintMessage(fmt.Sprintf("Error sending message to %s: %v", client.publicKeyID, err))
			}
		}
	}
}

// forceCloseRemainingConnections closes all client connections.
func (s *Server) forceCloseRemainingConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, client := range s.clients {
		client.conn.Close()
	}
	s.clients = make(map[string]*Client)
}

// addClient adds a new client to the server.
func (s *Server) addClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.publicKeyID] = client
	s.terminal.PrintMessage("Client connected: " + client.publicKeyID)
}

// removeClient removes a client from the server.
func (s *Server) removeClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.publicKeyID]; exists {
		delete(s.clients, client.publicKeyID)
		s.terminal.PrintMessage("Client disconnected: " + client.publicKeyID)
	}
}

// readPublicKey reads a client's public key from the connection.
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

// sendEncryptedSharedKey sends the shared AES key to the client.
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

func (s *Server) handleInterrupt(sigChan <-chan os.Signal) {
	<-sigChan
	fmt.Println("\r\nReceived interrupt signal. Exiting...\r")
	s.Close()
	os.Exit(0)
}

// askYesNo prompts the user with a question and expects a yes/no response.
func askYesNo(prompt string, terminal *gochatterminal.Terminal) bool {
	for {
		response, err := terminal.ReadLineWithPrompt(prompt)
		if err != nil {
			terminal.PrintMessage("Error reading input. Please try again.")
			continue
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response == "yes" || response == "y" {
			return true
		}
		if response == "no" || response == "n" {
			return false
		}
		terminal.PrintMessage("Please answer 'yes' or 'no'.")
	}
}

func main() {
	var debug = false
	if debug {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.Discard)
	}

	terminal, err := gochatterminal.NewTerminal("> ")
	if err != nil {
		log.Fatalf("Failed to create terminal: %v", err)
	}

	server := NewServer(20*time.Second, terminal)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go server.handleInterrupt(sigChan)

	// Run the server
	if err := server.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	} else {
		server.Close()
}
}
