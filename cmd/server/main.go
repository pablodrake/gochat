// main.go
package main

// TODO: Eliminate the bine dependency and use the tor package from the standard library
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

// Client struct with closed flag and mutex
type Client struct {
	conn        net.Conn
	publicKey   *rsa.PublicKey
	publicKeyID string
	closed      bool
	mu          sync.Mutex
}

type Server struct {
	clients           map[string]*Client
	mu                sync.RWMutex
	heartbeatInterval time.Duration
	sharedKey         []byte
	listener          net.Listener
	terminal          *gochatterminal.Terminal
	restorePrompt     bool

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
		restorePrompt:     true,
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
			s.terminal.PrintMessage("Failed to start Tor: "+err.Error(), s.restorePrompt)
			retry := s.terminal.AskYesNo("Do you want to try starting Tor again? [yes/no]: ")
			if !retry {
				return nil // Normal termination
			}
			continue
		}
		defer t.Close()

		onion, err := t.Listen(context.Background(), &tor.ListenConf{RemotePorts: []int{9999}, Version3: true})
		if err != nil {
			s.terminal.PrintMessage("Failed to create onion service: "+err.Error(), true)
			retry := s.terminal.AskYesNo("Do you want to try creating the onion service again? [yes/no]: ")
			if !retry {
				return nil // Normal termination
			}
			continue
		}
		s.listener = onion

		if err := s.terminal.SetRawMode(); err != nil {
			s.terminal.PrintMessage("Could not set terminal raw mode "+err.Error(), false)
			return err
		}
		s.terminal.PrintMessage("Server started. Connect with: "+onion.ID+".onion:9999", s.restorePrompt)

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
		retry := s.terminal.AskYesNo("Do you want to start another server? [yes/no]: ")
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
				s.terminal.PrintMessage("Listener error: "+err.Error(), s.restorePrompt)
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
		s.terminal.PrintMessage("Failed to read public key: "+err.Error(), s.restorePrompt)
		return
	}

	publicKeyID := gochatcrypto.PublicKeyIdentifier(publicKey)

	err = s.sendEncryptedSharedKey(conn, publicKey)
	if err != nil {
		s.terminal.PrintMessage("Failed to send encrypted shared key to "+publicKeyID+": "+err.Error(), s.restorePrompt)
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
					s.terminal.PrintMessage("Error reading from "+publicKeyID+": "+err.Error(), s.restorePrompt)
				}
				return
			}
			if message == "" {
				continue
			} else if message == "heartbeat" {
				err = s.sendAESEncryptedMessage(conn, []byte("heartbeat ack"))
				if err != nil {
					s.terminal.PrintMessage("Failed to send heartbeat ack to "+publicKeyID+": "+err.Error(), s.restorePrompt)
					return
				}
			} else {
				s.broadcastMessage(message, client)
				s.terminal.PrintMessage(message, s.restorePrompt)
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
				s.terminal.PrintMessage("Error reading input: "+err.Error(), s.restorePrompt)
				continue
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "/") {
				// Command parsing
				fields := strings.Fields(line)
				command := fields[0]
				args := fields[1:]

				switch command {
				case "/exit":
					s.signalDone()
					return
				case "/kick":
					if len(args) < 1 {
						s.terminal.PrintMessage("Usage: /kick <client_id>", s.restorePrompt)
						continue
					}
					clientID := args[0]
					client := s.getClientbyId(clientID)
					if client != nil {
						s.removeClient(client)
					} else {
						s.terminal.PrintMessage("Client not found", s.restorePrompt)
					}
				case "/broadcast":
					if len(args) < 1 {
						s.terminal.PrintMessage("Usage: /broadcast <message>", s.restorePrompt)
						continue
					}
					message := strings.Join(args, " ")
					s.broadcastMessage("Server: "+message, nil)
				case "/msg":
					if len(args) < 2 {
						s.terminal.PrintMessage("Usage : /msg <client_id> <message>", s.restorePrompt)
						continue
					}
					message := strings.Join(args[1:], " ")
					clientID := args[0]
					client := s.getClientbyId(clientID)
					if client != nil {
						s.sendServerMessage("Server: "+message, client)
					} else {
						s.terminal.PrintMessage("Client not found", s.restorePrompt)
					}
				default:
					s.terminal.PrintMessage("Unknown command: "+command, s.restorePrompt)
				}
			} else {
				continue
			}
		}
	}
}

// shutdown initiates the server shutdown process.
func (s *Server) Close() {
	s.restorePrompt = false
	s.terminal.Close()
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

// Enhanced sendAESEncryptedMessage method
func (s *Server) sendAESEncryptedMessage(conn net.Conn, message []byte) error {
	encryptedMessage, err := gochatcrypto.EncryptWithAES(s.sharedKey, message)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %v", err)
	}

	encodedMessage := base64.StdEncoding.EncodeToString(encryptedMessage) + "\n"
	_, err = conn.Write([]byte(encodedMessage))
	if err != nil {
		if strings.Contains(err.Error(), "use of closed network connection") {
			// Ignore the error if the connection is closed
			return nil
		}
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
				s.terminal.PrintMessage("Error sending message to "+client.publicKeyID+" : "+err.Error(), s.restorePrompt)
			}
		}
	}
}

func (s *Server) sendServerMessage(message string, client *Client) error {
	err := s.sendAESEncryptedMessage(client.conn, []byte(message))
	if err != nil {
		return fmt.Errorf("error sending message to %s: %v", client.publicKeyID, err)
	}
	return nil
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
	s.terminal.PrintMessage("Client connected: "+client.publicKeyID, s.restorePrompt)
}

// Modified removeClient method
func (s *Server) removeClient(client *Client) {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return
	}
	client.closed = true
	client.mu.Unlock()

	// Attempt to send "kicked" message
	_ = s.sendServerMessage("kicked", client)

	// Lock the server's client map
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close the connection and remove the client
	client.conn.Close()
	if _, exists := s.clients[client.publicKeyID]; exists {
		delete(s.clients, client.publicKeyID)
		s.terminal.PrintMessage("Client disconnected: "+client.publicKeyID, s.restorePrompt)
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

func (s *Server) getClientbyId(clientID string) *Client {
	client, exists := s.clients[clientID]
	if !exists {
		s.terminal.PrintMessage("Client not found: "+clientID, s.restorePrompt)
		return nil
	}
	return client
}

func main() {
	var debug = false
	if debug {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.Discard)
	}

	terminal, err := gochatterminal.NewTerminal("")
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
		server.terminal.PrintMessage("Exiting app", false)
		server.Close()
	}
}
