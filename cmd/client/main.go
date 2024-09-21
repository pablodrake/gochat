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

	"github.com/pablodrake/gochat/gochatcrypto"
	"github.com/pablodrake/gochat/gochatterminal"
	"golang.org/x/net/proxy"
)

// Client represents the chat client.
type Client struct {
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	publicKeyID string
	sharedKey   []byte

	conn      net.Conn
	connMutex sync.Mutex // Protects conn

	terminal *gochatterminal.Terminal

	done chan struct{}
	once sync.Once
}

// NewClient initializes a new Client instance.
func NewClient(terminal *gochatterminal.Terminal) *Client {
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
        // Reset done channel and once variable at the beginning of each iteration
        c.done = make(chan struct{})
        c.once = sync.Once{}

        // Establish connection
        if err := c.establishConnection(); err != nil {
            c.terminal.PrintMessage(fmt.Sprintf("Failed to establish connection: %v", err))
            retry := askYesNo("Do you want to connect to another server? [yes/no]: ", c.terminal)
            if !retry {
                return nil // Normal termination
            }
            continue
        }

        c.terminal.PrintMessage("Successfully connected to the chat server!")

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
			} else if line == "/exit" {
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

    // Start a goroutine to close the connection when context is done
    go func() {
        <-ctx.Done()
        c.connMutex.Lock()
        if c.conn != nil {
            c.conn.Close()
            c.conn = nil
        }
        c.connMutex.Unlock()
    }()

    for {
        encryptedMessage, err := reader.ReadString('\n')
        if err != nil {
            if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
                // Connection closed, exit the goroutine
                c.signalDone()
                return
            } else {
                log.Printf("Error reading from server: %v", err)
                c.signalDone()
                return
            }
        }

        message, err := c.processIncomingMessage(encryptedMessage)
        if err != nil {
            log.Printf("Error processing message: %v", err)
        } else if message != "" {
            c.terminal.PrintMessage(message)
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
                    if strings.Contains(err.Error(), "use of closed network connection") {
                        // Connection has been closed, exit the goroutine
                        c.connMutex.Unlock()
                        return
                    }
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
	for {
		choice, err := c.terminal.ReadLineWithPrompt("Do you want to generate a new key pair or use existing? [generate/use]: ")
		if err != nil {
			return fmt.Errorf("failed to read choice: %w", err)
		}

		choice = strings.TrimSpace(strings.ToLower(choice))

		switch choice {
		case "generate":
			if err := c.generateKeys(); err != nil {
				c.terminal.PrintMessage("Error generating keys: " + err.Error())
				continue // Re-prompt the user
			}
			return nil // Successful key generation
		case "use":
			if err := c.loadKeys(); err != nil {
				c.terminal.PrintMessage("Error loading keys: " + err.Error())
				continue // Re-prompt the user
			}
			return nil // Successful key loading
		default:
			c.terminal.PrintMessage("Invalid choice. Please enter 'generate' or 'use'.")
			// Loop continues to re-prompt the user
		}
	}
}

// generateKeys creates a new RSA key pair and loads them.
func (c *Client) generateKeys() error {
	err := gochatcrypto.GenerateRSAKeys("private.pem", "public.pem")
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}
	c.terminal.PrintMessage("Keys generated and saved to 'private.pem' and 'public.pem'")
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
	message = c.handleServerMessage(message)
	return message, nil
}

// handleServerMessage processes server messages.
func (c *Client) handleServerMessage(message string) (handledMessage string) {
	// Check for shutdown message
  handledMessage = ""
	if message == "Server is shutting down. Goodbye!" {
		c.terminal.PrintMessage("Server has disconnected.")
		c.signalDone()
	} else if message == "heartbeat ack" {
    //TODO: Fix loging, maybe write to file
    log.Printf("Received heartbeat from server\r\n") 
  } else {
    handledMessage = message
  }
  return handledMessage
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
	var debug bool = false
	if debug {
    logFile, err := os.Create("gochatLogs")
    if err != nil {
      log.Fatalf("Error creating log file: %v", err)
      return
    }
    defer logFile.Close()

		log.SetOutput(logFile)
	} else {
		log.SetOutput(io.Discard)
	}

  terminal, err := gochatterminal.NewTerminal("> ")
  if err != nil {
      log.Fatalf("Error creating terminal: %v", err)
  }

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
