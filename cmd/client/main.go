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

	"github.com/pablodrake/gochat/gochatcrypto"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Global mutex to synchronize terminal output
var stdoutMutex sync.Mutex

// Terminal struct handles user input and terminal state
type Terminal struct {
	inputRequests chan InputRequest
	history       []string
	prompt        string
	currentLine   string
	mu            sync.Mutex // Protects currentLine
	oldState      *term.State
}

// InputRequest represents a request for user input.
type InputRequest struct {
	Prompt   string
	Response chan string
}

// NewTerminal initializes a new Terminal instance.
func NewTerminal(prompt string) *Terminal {
	t := &Terminal{
		inputRequests: make(chan InputRequest),
		prompt:        prompt,
	}

	fd := int(os.Stdin.Fd())

	// Save the old terminal state
	oldState, err := term.GetState(fd)
	if err != nil {
		log.Fatalf("Failed to get terminal state: %v", err)
	}

	// Put the terminal into raw mode
	_, err = term.MakeRaw(fd)
	if err != nil {
		log.Fatalf("Failed to set terminal to raw mode: %v", err)
	}

	// Retrieve the current terminal attributes
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		log.Fatalf("Failed to get terminal attributes: %v", err)
	}

	// Re-enable ISIG to allow signal generation from characters like Ctrl+C
	termios.Lflag |= unix.ISIG

	// Apply the modified terminal attributes
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		log.Fatalf("Failed to set terminal attributes: %v", err)
	}

	t.oldState = oldState

	go t.inputManager()
	return t
}

func (t *Terminal) inputManager() {
	for req := range t.inputRequests {
		stdoutMutex.Lock()
		fmt.Print("\r" + req.Prompt) // Move to the start of the line before printing the prompt
		stdoutMutex.Unlock()

		var line []rune
		t.mu.Lock()
		t.currentLine = "" // Initialize currentLine
		t.mu.Unlock()

		for {
			// Read a single byte
			var buf [1]byte
			n, err := os.Stdin.Read(buf[:])
			if err != nil || n == 0 {
				log.Printf("Error reading input: %v", err)
				req.Response <- ""
				break
			}
			r := rune(buf[0])

			if r == '\r' || r == '\n' {
				// Newline detected, process the line
				inputLine := string(line)
				t.history = append(t.history, inputLine)
				req.Response <- inputLine
				line = nil // Clear the line
				t.mu.Lock()
				t.currentLine = "" // Clear currentLine
				t.mu.Unlock()
				stdoutMutex.Lock()
				fmt.Print("\r\n") // Move to the next line
				stdoutMutex.Unlock()
				break
			} else if r == 127 || r == '\b' {
				// Handle backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					t.mu.Lock()
					t.currentLine = string(line)
					t.mu.Unlock()

					// Erase character from terminal
					stdoutMutex.Lock()
					fmt.Print("\b \b") // Move back, clear, and move back again
					stdoutMutex.Unlock()
				}
			} else if r == 3 {
				// Handle Ctrl+C
				stdoutMutex.Lock()
				fmt.Print("^C\r\n")
				stdoutMutex.Unlock()
				req.Response <- "exit"
				break
			} else if r == 4 {
				// Handle Ctrl+D (EOF)
				req.Response <- ""
				return
			} else {
				// Add the rune to the line
				line = append(line, r)
				t.mu.Lock()
				t.currentLine = string(line)
				t.mu.Unlock()

				// Echo the character
				stdoutMutex.Lock()
				fmt.Print(string(r))
				stdoutMutex.Unlock()
			}
		}
	}
}

// ReadLine reads a line from the terminal using the default prompt.
func (t *Terminal) ReadLine() (string, error) {
	return t.ReadLineWithPrompt(t.prompt)
}

// ReadLineWithPrompt reads a line using a specified prompt.
func (t *Terminal) ReadLineWithPrompt(prompt string) (string, error) {
	responseChan := make(chan string)
	t.inputRequests <- InputRequest{
		Prompt:   prompt,
		Response: responseChan,
	}
	line := <-responseChan
	return line, nil
}

func (t *Terminal) clearCurrentInput() {
	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()
	fmt.Print("\r\033[K") // Move cursor to start of line and clear the line
}

// SetPrompt updates the terminal prompt.
func (t *Terminal) SetPrompt(prompt string) {
	t.prompt = prompt
}

// Close terminates the input manager goroutine and restores terminal state.
func (t *Terminal) Close() {
	close(t.inputRequests)
	term.Restore(int(os.Stdin.Fd()), t.oldState)
}

// Client represents the chat client.
type Client struct {
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	publicKeyID string
	sharedKey   []byte

	conn      net.Conn
	connMutex sync.Mutex // Protects conn

	terminal *Terminal

	done chan struct{}
	once sync.Once
}

// NewClient initializes a new Client instance.
func NewClient(terminal *Terminal) *Client {
	return &Client{
		terminal: terminal,
		done:     make(chan struct{}),
	}
}

// Run starts the client's main loop.
func (c *Client) Run() error {
	// Handle key setup
	if err := c.handleKeySetup(); err != nil {
		return fmt.Errorf("key setup failed: %v", err)
	}

	for {
		// Establish connection
		if err := c.establishConnection(); err != nil {
			fmt.Printf("Failed to establish connection: %v\n", err)
			retry := askYesNo("Do you want to try again? [yes/no]: ", c.terminal)
			if !retry {
				return nil // Normal termination
			}
			continue
		}

		fmt.Println("Successfully connected to the chat server!")

		// Create a new context for this connection session
		ctx, cancel := context.WithCancel(context.Background())

		// Start goroutines
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			c.handleInput(ctx)
		}()
		go func() {
			defer wg.Done()
			c.readMessages(ctx)
		}()
		go func() {
			defer wg.Done()
			c.sendHeartbeat(ctx)
		}()

		// Wait for done signal
		<-c.done

		// Cancel the context to signal all goroutines to stop
		cancel()

		// Wait for all goroutines to finish
		wg.Wait()

		// Cleanup
		c.cleanupConnection()

		// Prompt for reconnection
		retry := askYesNo("Do you want to connect to a new server? [yes/no]: ", c.terminal)
		if !retry {
			return nil // Normal termination
		}
	}
}

// handleInput manages user input and sends messages.
func (c *Client) handleInput(ctx context.Context) {
	c.terminal.SetPrompt("> ")
	for {
		select {
		case <-ctx.Done():
			return
		default:
			line, err := c.terminal.ReadLine()
			if err != nil {
				if err == io.EOF {
					// Terminal closed
					return
				}
				log.Printf("Error reading input: %v", err)
				continue
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if line == "exit" {
				fmt.Println("Disconnecting from chat server...")
				c.signalDone()
				return
			}

			c.sendMessage(line)
		}
	}
}

// readMessages listens for messages from the server, decrypts, and displays them.
func (c *Client) readMessages(ctx context.Context) {
	reader := bufio.NewReader(c.conn)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			encryptedMessage, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					fmt.Println("\nServer has disconnected. (Press enter to continue)")
				} else {
					log.Printf("Error reading from server: %v", err)
				}
				c.signalDone()
				return
			}

			message, err := c.processIncomingMessage(encryptedMessage)
			if err != nil {
				log.Printf("Error processing message: %v", err)
			} else {
				c.terminal.mu.Lock()
				line := c.terminal.currentLine
				c.terminal.mu.Unlock()

				c.terminal.clearCurrentInput()

				stdoutMutex.Lock()
				fmt.Println("\r" + message)
				fmt.Print("\r" + c.terminal.prompt + line)
				stdoutMutex.Unlock()
			}
		}
	}
}

// sendHeartbeat periodically sends heartbeat messages to the server.
func (c *Client) sendHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.connMutex.Lock()
			if c.conn != nil {
				_, err := fmt.Fprintf(c.conn, "heartbeat\n")
				if err != nil {
					log.Printf("Error sending heartbeat: %v", err)
					c.connMutex.Unlock()
					c.signalDone()
					return
				}
			}
			c.connMutex.Unlock()
		}
	}
}

// signalDone safely closes the done channel once.
func (c *Client) signalDone() {
	c.once.Do(func() {
		close(c.done)
	})
}

// Close signals all goroutines to exit and cleans up resources.
func (c *Client) Close() {
	c.signalDone()
	c.cleanupConnection()
	c.terminal.Close()
}

// handleKeySetup manages the key generation or loading process.
func (c *Client) handleKeySetup() error {
	choice, err := c.terminal.ReadLineWithPrompt("Do you want to generate a new key pair or use existing? [generate/use]: ")
	if err != nil {
		return fmt.Errorf("failed to read choice: %w", err)
	}

	switch choice {
	case "generate":
		return c.generateKeys()
	case "use":
		return c.loadKeys()
	default:
		return fmt.Errorf("invalid choice: %s", choice)
	}
}

// generateKeys creates a new RSA key pair and loads them.
func (c *Client) generateKeys() error {
	err := gochatcrypto.GenerateRSAKeys("private.pem", "public.pem")
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}
	fmt.Println("Keys generated and saved to 'private.pem' and 'public.pem'")
	return c.loadKeysFromFiles("private.pem", "public.pem")
}

// loadKeys prompts the user to provide paths to existing keys and loads them.
func (c *Client) loadKeys() error {
	privateKeyPath, err := c.terminal.ReadLineWithPrompt("Enter the path to your PEM-encoded private key: ")
	if err != nil {
		return fmt.Errorf("failed to read private key path: %w", err)
	}

	publicKeyPath, err := c.terminal.ReadLineWithPrompt("Enter the path to your PEM-encoded public key: ")
	if err != nil {
		return fmt.Errorf("failed to read public key path: %w", err)
	}

	return c.loadKeysFromFiles(privateKeyPath, publicKeyPath)
}

// loadKeysFromFiles loads the RSA keys from the specified file paths.
func (c *Client) loadKeysFromFiles(privateKeyPath, publicKeyPath string) error {
	var err error
	c.privateKey, err = gochatcrypto.LoadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	c.publicKey, err = gochatcrypto.LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	c.publicKeyID = gochatcrypto.PublicKeyIdentifier(c.publicKey)
	return nil
}

// establishConnection connects to the chat server and sets up encryption.
func (c *Client) establishConnection() error {
	publicKeyPEM, err := gochatcrypto.PublicKeyToPEM(c.publicKey)
	if err != nil {
		return fmt.Errorf("failed to export public key: %w", err)
	}

	address, err := c.terminal.ReadLineWithPrompt("Enter the chat server address (example: xyz.onion:9999): ")
	if err != nil {
		return fmt.Errorf("failed to read address: %w", err)
	}

	if err := c.connectToServer(address, publicKeyPEM); err != nil {
		return err
	}
	return nil
}

// connectToServer dials the server through Tor SOCKS5 proxy and exchanges keys.
func (c *Client) connectToServer(address, publicKeyPEM string) error {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("error connecting to proxy: %w", err)
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("error connecting to chat server: %w", err)
	}

	// Send public key
	_, err = fmt.Fprintf(conn, "%s\n", publicKeyPEM)
	if err != nil {
		conn.Close()
		return fmt.Errorf("error sending public key: %w", err)
	}

	// Receive and decrypt the shared key
	reader := bufio.NewReader(conn)
	encryptedSharedKeyBase64, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return fmt.Errorf("error reading shared key: %w", err)
	}

	encryptedSharedKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptedSharedKeyBase64))
	if err != nil {
		conn.Close()
		return fmt.Errorf("error decoding shared key: %w", err)
	}

	sharedKey, err := gochatcrypto.DecryptWithRSA(c.privateKey, encryptedSharedKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("error decrypting shared key: %w", err)
	}

	c.sharedKey = sharedKey

	// Safely assign the connection
	c.connMutex.Lock()
	c.conn = conn
	c.connMutex.Unlock()

	return nil
}

// sendMessage handles user input and sends encrypted messages to the server.
func (c *Client) sendMessage(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	if line == "exit" {
		fmt.Println("Disconnecting from chat server...")
		c.signalDone()
		return
	}

	message := fmt.Sprintf("%s: %s", c.publicKeyID, line)

	encodedMessage, err := c.processOutgoingMessage(message)
	if err != nil {
		log.Printf("Error processing outgoing message: %v", err)
		return
	}

	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if c.conn != nil {
		_, err := fmt.Fprintf(c.conn, "%s\n", encodedMessage)
		if err != nil {
			log.Printf("Error sending message: %v", err)
			c.signalDone()
			return
		}
	}
}

func (c *Client) processOutgoingMessage(message string) (string, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return "", nil
	}

	// Encrypt with AES
	encryptedMessage, err := gochatcrypto.EncryptWithAES(c.sharedKey, []byte(message))
	if err != nil {
		log.Printf("Error encrypting message: %v", err)
		return "", err
	}

	// Encode to base64
	encodedMessage := base64.StdEncoding.EncodeToString(encryptedMessage)
	return encodedMessage, nil
}

// processIncomingMessage decrypts and handles incoming messages.
func (c *Client) processIncomingMessage(encryptedMessage string) (string, error) {
	encryptedMessage = strings.TrimSpace(encryptedMessage)
	if encryptedMessage == "" {
		return "", nil
	}

	// Decode base64
	decodedMessage, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		log.Printf("Error decoding message: %v", err)
		return "", err
	}

	// Decrypt with AES
	decryptedText, err := gochatcrypto.DecryptWithAES(c.sharedKey, decodedMessage)
	if err != nil {
		log.Printf("Error decrypting message: %v", err)
		return "", err
	}

	message := string(decryptedText)
	c.handleServerMessage(message)
	return message, nil
}

// handleServerMessage processes server messages.
func (c *Client) handleServerMessage(message string) {
	// Check for shutdown message
	if message == "Server is shutting down. Goodbye!" {
		fmt.Println("Server has disconnected.")
		c.signalDone()
	}
}

// cleanupConnection closes the connection and performs any necessary cleanup.
func (c *Client) cleanupConnection() {
	// Close the connection
	c.connMutex.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMutex.Unlock()
}

// handleInterrupt listens for OS interrupt signals and triggers immediate shutdown.
func (c *Client) handleInterrupt(sigChan <-chan os.Signal) {
	<-sigChan
	c.Close()
	fmt.Println("\nReceived interrupt signal. Exiting...")
	os.Exit(0)
}

// askYesNo prompts the user with a question and expects a yes/no response.
func askYesNo(prompt string, terminal *Terminal) bool {
	for {
		response, err := terminal.ReadLineWithPrompt(prompt)
		if err != nil {
			fmt.Println("Error reading input. Please try again.")
			continue
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response == "yes" || response == "y" {
			return true
		}
		if response == "no" || response == "n" {
			return false
		}
		fmt.Println("Please answer 'yes' or 'no'.")
	}
}

func main() {
	var debug bool = false
	if debug {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.Discard)
	}

	// Create Terminal
	terminal := NewTerminal("> ")

	client := NewClient(terminal)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go client.handleInterrupt(sigChan)

	// Run the client
	if err := client.Run(); err != nil {
		log.Fatalf("Client error: %v", err)
	}

	// No need to call Close() here as Run handles cleanup
}
