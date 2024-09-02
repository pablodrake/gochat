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
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/pablodrake/gochat/gochatcrypto"
	"golang.org/x/net/proxy"
)

type Client struct {
	conn        net.Conn
	publicKey   *rsa.PublicKey
    publickeyId string
	privateKey  *rsa.PrivateKey
	sharedKey   []byte
	rl          *readline.Instance
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
}


func main() {
	var debug bool = false
	if debug {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.Discard)
	}

	client, err := NewClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if err := client.Run(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}

func NewClient() (*Client, error) {
	rl, err := readline.New("> ")
	if err != nil {
		return nil, fmt.Errorf("readline initialization failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	return &Client{
		rl:     rl,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}, nil
}

func (c *Client) Run() error {
	reader := bufio.NewReader(os.Stdin)

	if err := c.handleKeySetup(reader); err != nil {
		return fmt.Errorf("key setup failed: %v", err)
	}

	if err := c.establishConnection(reader); err != nil {
		return fmt.Errorf("failed to establish connection: %v", err)
	}
	defer c.conn.Close()

	fmt.Println("Successfully connected to the chat server!")

	go c.handleInterrupt()
	go c.sendHeartbeat()
	go c.readMessages()

	c.sendMessages()

	<-c.done
	fmt.Println("You have disconnected from the chat server.")
	return nil
}

func (c *Client) Close() {
	c.rl.Close()
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) handleKeySetup(reader *bufio.Reader) error {
	fmt.Print("Do you want to generate new key pair or use existing? [generate/use]: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read choice: %w", err)
	}
	choice = strings.TrimSpace(choice)

	switch choice {
	case "generate":
		return c.generateKeys()
	case "use":
		return c.loadKeys(reader)
	default:
		return fmt.Errorf("invalid choice: %s", choice)
	}
}

func (c *Client) generateKeys() error {
	err := gochatcrypto.GenerateRSAKeys("private.pem", "public.pem")
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}
	fmt.Println("Keys generated and saved to 'private.pem' and 'public.pem'")
	return c.loadKeysFromFiles("private.pem", "public.pem")
}

func (c *Client) loadKeys(reader *bufio.Reader) error {
	fmt.Print("Enter the path to your PEM-encoded private key: ")
	privateKeyPath, _ := reader.ReadString('\n')
	privateKeyPath = strings.TrimSpace(privateKeyPath)

	fmt.Print("Enter the path to your PEM-encoded public key: ")
	publicKeyPath, _ := reader.ReadString('\n')
	publicKeyPath = strings.TrimSpace(publicKeyPath)

	return c.loadKeysFromFiles(privateKeyPath, publicKeyPath)
}

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
    c.publickeyId = gochatcrypto.PublicKeyIdentifier(c.publicKey)
	return nil
}

func (c *Client) establishConnection(reader *bufio.Reader) error {
	publicKeyPEM, err := gochatcrypto.PublicKeyToPEM(c.publicKey)
	if err != nil {
		return fmt.Errorf("failed to export public key: %w", err)
	}

	for {
		fmt.Print("Enter the chat server address (example: xyz.onion:9999): ")
		address, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read address: %w", err)
		}
		address = strings.TrimSpace(address)

		if err := c.connectToServer(address, publicKeyPEM); err != nil {
			fmt.Println("Error connecting to server:", err)
			fmt.Println("Make sure the Tor proxy is running and the server address is correct.")
			continue
		}
		return nil
	}
}

func (c *Client) connectToServer(address, publicKeyPEM string) error {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("error connecting to proxy: %w", err)
	}

	c.conn, err = dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("error connecting to chat server: %w", err)
	}

	fmt.Fprintf(c.conn, "%s\n", publicKeyPEM)

	// Receive and decrypt the shared key
	reader := bufio.NewReader(c.conn)
	encryptedSharedKeyBase64, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading shared key: %w", err)
	}

	encryptedSharedKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptedSharedKeyBase64))
	if err != nil {
		return fmt.Errorf("error decoding shared key: %w", err)
	}

	c.sharedKey, err = gochatcrypto.DecryptWithRSA(c.privateKey, encryptedSharedKey)
	if err != nil {
		return fmt.Errorf("error decrypting shared key: %w", err)
	}

	return nil
}

func (c *Client) handleInterrupt() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	select {
	case <-ch:
		fmt.Println("\nReceived interrupt signal. Disconnecting...")
	case <-c.ctx.Done():
		fmt.Println("\nDisconnecting...")
	}

	c.cancel()
	c.conn.Close()
	c.rl.Clean()
	close(c.done)
}

func (c *Client) readMessages() {
	reader := bufio.NewReader(c.conn)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			encryptedMessage, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from server: %v", err)
				}
				return
			}
			
			// Decode the base64 encoded message
			decodedMessage, err := base64.StdEncoding.DecodeString(encryptedMessage)
			if err != nil {
				log.Printf("Error decoding message: %v", err)
				continue
			}
			
			// Decrypt the message
			decryptedText, err := gochatcrypto.DecryptWithAES(c.sharedKey, decodedMessage)
			if err != nil {
				log.Printf("Error decrypting message: %v", err)
				continue
			}
			
			message := string(decryptedText)
			if message == "heartbeat ack" {
				log.Println("Received heartbeat ack")
				continue
			}

			
			currentPrompt := c.rl.Config.Prompt
			fmt.Print("\r\033[K")
			fmt.Println(message)
			c.rl.SetPrompt(currentPrompt)
			c.rl.Refresh()
		}
	}
}

func (c *Client) sendMessages() {
	for {
		line, err := c.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				c.cancel()
				return
			}
			log.Printf("Error reading message: %v", err)
			return
		}
		if line == "exit" {
			fmt.Println("Disconnecting from chat server...")
			c.cancel()
			return
		}
		select {
		case <-c.ctx.Done():
			return
		default:
			encryptedMessage, err := gochatcrypto.EncryptWithAES(c.sharedKey, []byte(c.publickeyId + ": " + line))
			if err != nil {
				log.Printf("Error encrypting message: %v", err)
				continue
			}
			encodedMessage := base64.StdEncoding.EncodeToString(encryptedMessage)
			_, err = c.conn.Write([]byte(encodedMessage + "\n"))
			if err != nil {
				log.Printf("Error sending message: %v", err)
				return
			}
		}
	}
}


func (c *Client) sendHeartbeat() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, err := c.conn.Write([]byte("heartbeat\n"))
			if err != nil {
				log.Printf("Error sending heartbeat: %v", err)
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}
