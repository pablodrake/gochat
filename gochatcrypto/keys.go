// File: /crypto/keys.go
package gochatcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
    "encoding/hex"
)

// GenerateRSAKeys generates and saves an RSA private and public key pair to files.
func GenerateRSAKeys(privatePath, publicPath string) error {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return err
    }

    // Save the private key
    privateFile, err := os.Create(privatePath)
    if err != nil {
        return err
    }
    defer privateFile.Close()
    privatePem := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    }
    if err := pem.Encode(privateFile, privatePem); err != nil {
        return err
    }

    // Save the public key
    publicFile, err := os.Create(publicPath)
    if err != nil {
        return err
    }
    defer publicFile.Close()
    publicKey := &privateKey.PublicKey
    publicPem := &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: x509.MarshalPKCS1PublicKey(publicKey),
    }
    return pem.Encode(publicFile, publicPem)
}

// ParseRSAPublicKey parses a PEM-encoded public key from a string.
func ParseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pemStr))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the public key")
    }

    // Parse the public key using x509.ParsePKIXPublicKey
    pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse public key: %w", err)
    }

    return pub, nil
}

// ParseRSAPrivateKey parses a PEM-encoded private key from a string.
func ParseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(pemStr))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the private key")
    }

    // Parse the private key using x509.ParsePKCS1PrivateKey
    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse private key: %w", err)
    }
    return priv, nil
}

// CheckKeyPair checks if a given private and public key are a valid pair.
func CheckKeyPair(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) bool {
    // Encrypt a sample message using the public key
    message := []byte("test")
    label := []byte("")
    hash := sha256.New()
    ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, message, label)
    if err != nil {
        return false
    }

    // Decrypt the message using the private key
    plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, label)
    if err != nil {
        return false
    }

    // Check if decrypted message matches original
    return string(plaintext) == string(message)
}

// LoadRSAPublicKey loads an RSA public key from a file.
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
    pemBytes, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to parse PEM block containing the key")
    }

    pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    return pub, nil
}

// LoadRSAPrivateKey loads an RSA private key from a file.
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
    pemBytes, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to parse PEM block containing the key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    return priv, nil
}

// PublicKeyToPEM converts an RSA public key to a PEM-encoded string
func PublicKeyToPEM(pubKey *rsa.PublicKey) (string, error) {
    publicKeyBytes := x509.MarshalPKCS1PublicKey(pubKey)

    publicKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    })
    return string(publicKeyPEM), nil
}

// PublicKeyIdentifier creates a short, unique identifier for an RSA public key.
func PublicKeyIdentifier(pubKey *rsa.PublicKey) string {
    // Convert RSA public key to ASN.1 DER-encoded form
    pubASN1 := x509.MarshalPKCS1PublicKey(pubKey)


    // Compute a SHA-256 hash of the DER-encoded public key
    hash := sha256.Sum256(pubASN1)
    return hex.EncodeToString(hash[:])  // Return the hexadecimal encoding of the hash
}

func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256 requires a 32-byte key
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}