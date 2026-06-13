package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"chatmail/internal/database"
	"chatmail/internal/imap"
	"chatmail/internal/smtp"
)

func main() {
	// Initialize directory first
	_ = os.MkdirAll("/var/lib/chatmail", 0755)

	// Set up dual logging to both standard output and log file
	logFilePath := "/var/lib/chatmail/chatmail.log"
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		defer logFile.Close()
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	} else {
		log.Printf("Warning: Could not open log file at %s: %v", logFilePath, err)
	}

	log.Println("Starting Minimal Chatmail Server Core Process...")

	// 1. Initialize Bbolt Database
	dbPath := "/var/lib/chatmail/chatmail.db"
	db, err := database.NewBboltDB(dbPath)
	if err != nil {
		log.Fatalf("Initialization of Bbolt Database failed: %v", err)
	}
	defer db.Close()
	log.Printf("Bbolt Database mapped successfully from %s", dbPath)

	// startErrCh receives the first fatal startup error from either server.
	// Buffered to 2 so goroutines never block even if main has already exited.
	startErrCh := make(chan error, 2)

	// 2. Spawn Plaintext SMTP Engine (Inbound Routing)
	smtpServer := smtp.NewServer("127.0.0.1:1025", db)
	go func() {
		log.Println("SMTP Engine listening on 127.0.0.1:1025 (Behind Stunnel4 587)")
		if err := smtpServer.ListenAndServe(); err != nil {
			startErrCh <- fmt.Errorf("SMTP engine: %w", err)
		}
	}()

	// 3. Spawn Plaintext IMAP Engine (Index/Sync Engine)
	imapServer := imap.NewServer("127.0.0.1:1143", db)
	go func() {
		log.Println("IMAP Engine listening on 127.0.0.1:1143 (Behind Stunnel4 993)")
		if err := imapServer.ListenAndServe(); err != nil {
			startErrCh <- fmt.Errorf("IMAP engine: %w", err)
		}
	}()

	// 4. Capture OS Signals for Clean Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v. Performing transactional Bbolt Sync & Shutdown...", sig)
	case err := <-startErrCh:
		log.Fatalf("Server startup error: %v", err)
	}

	smtpServer.Close()
	imapServer.Close()
	log.Println("Server processes cleanly shut down.")
}
