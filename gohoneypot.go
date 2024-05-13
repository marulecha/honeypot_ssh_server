package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {

	// Open or create a log file
	logFile, err := os.OpenFile("logfile.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	// Set log output to the file

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Encode private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Save private key to a file
	privateKeyFile, err := os.Create("private.pem")
	if err != nil {
		log.Fatalf("Failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		log.Fatalf("Failed to write private key to file: %v", err)
	}

	log.Println("Private key generated and saved to private.pem")

	// SSH server configuration
	sshConfig := &ssh.ServerConfig{
		// Configure password callback function
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// Log authentication attempt
			log.Printf("Login attempt from %s with credentials -> '%s:%s'", conn.RemoteAddr(), conn.User(), string(password))
			// Deny access
			return nil, fmt.Errorf("authentication failed")
		},
	}

	// Add the private key to the server configuration
	privateKeySigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to create signer from private key: %v", err)
	}
	sshConfig.AddHostKey(privateKeySigner)

	// Start SSH server on port 2222
	listener, err := net.Listen("tcp", "localhost:2222")
	if err != nil {
		log.Fatalf("Failed to start SSH server: %v", err)
	}
	defer listener.Close()
	log.Println("SSH server listening on localhost:2222")

	// Accept incoming connections and handle them
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept incoming connection: %v", err)
		}

		// Handle SSH connection in a goroutine
		go handleSSHConnection(conn, sshConfig)
		log.SetOutput(logFile)
	}

}

func handleSSHConnection(conn net.Conn, config *ssh.ServerConfig) {
	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("SSH connection established from %s", sshConn.RemoteAddr())

	// Discard incoming channels
	go ssh.DiscardRequests(reqs)

	// Accept and handle incoming channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		// Accept the session channel
		channel, _, err := newChannel.Accept()
		if err != nil {
			log.Printf("Failed to accept session channel: %v", err)
			return
		}

		// Handle session channel in a goroutine
		go handleSession(channel)
	}
}

func handleSession(channel ssh.Channel) {
	defer channel.Close()

	// Example: echo back any input received
	// Here you can implement any custom behavior for the SSH session
	io.Copy(channel, channel)
}
