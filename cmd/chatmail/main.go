// Command chatmail is the entry point for the minimal chatmail server. It
// bootstraps the bbolt database, starts the plaintext SMTP and IMAP listeners
// (TLS is terminated externally by stunnel4), runs the daily retention sweep,
// and shuts everything down cleanly on SIGINT/SIGTERM.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"chatmail/internal/database"
	"chatmail/internal/imap"
	"chatmail/internal/smtp"
)

// version is set at build time via:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always --dirty)"
var version = "dev"

func main() {
	var (
		domain     = flag.String("domain", "local.chat", "local mail domain enforced for all addresses")
		dataDir    = flag.String("data-dir", "/var/lib/chatmail", "directory holding the bbolt database file")
		smtpAddr   = flag.String("smtp-addr", "127.0.0.1:1025", "plaintext SMTP listen address")
		imapAddr   = flag.String("imap-addr", "127.0.0.1:1143", "plaintext IMAP listen address")
		retention  = flag.Duration("retention", 30*24*time.Hour, "messages older than this are flagged \\Deleted by the sweep")
		sweepEvery = flag.Duration("sweep-interval", 24*time.Hour, "interval between retention sweeps")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmsgprefix)

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		logger.Fatalf("create data dir %q: %v", *dataDir, err)
	}
	dbPath := filepath.Join(*dataDir, "chatmail.db")
	db, err := database.Open(dbPath, *domain)
	if err != nil {
		logger.Fatalf("open database: %v", err)
	}
	defer db.Close()
	logger.Printf("chatmail %s started (domain=%s data=%s)", version, db.Domain(), dbPath)

	smtpServer := smtp.NewServer(db, *smtpAddr, logger)
	imapServer := imap.NewServer(db, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	// SMTP goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Printf("SMTP listening on %s", *smtpAddr)
		if err := smtpServer.ListenAndServe(); err != nil {
			select {
			case <-ctx.Done():
			default:
				logger.Printf("SMTP stopped unexpectedly: %v", err)
				stop()
			}
		}
	}()

	// IMAP goroutine — pre-bind the listener so we can report the error
	// before the accept loop starts and avoid a race with the WaitGroup.
	imapLn, err := net.Listen("tcp", *imapAddr)
	if err != nil {
		logger.Fatalf("listen IMAP %q: %v", *imapAddr, err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Printf("IMAP listening on %s", *imapAddr)
		if err := imapServer.Serve(imapLn); err != nil {
			select {
			case <-ctx.Done():
			default:
				logger.Printf("IMAP stopped unexpectedly: %v", err)
				stop()
			}
		}
	}()

	// Retention sweep goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runRetention(ctx, db, *retention, *sweepEvery, logger)
	}()

	<-ctx.Done()
	logger.Printf("shutdown signal received, closing listeners")

	_ = smtpServer.Close()
	_ = imapServer.Close()
	wg.Wait()
	logger.Printf("chatmail stopped")
}

// runRetention periodically flags messages older than maxAge for deletion.
// The first sweep fires shortly after startup (after a one-minute warm-up)
// so a freshly booted server reclaims storage promptly rather than waiting a
// full interval.
func runRetention(ctx context.Context, db *database.DB, maxAge, every time.Duration, logger *log.Logger) {
	// Run once a minute after startup, then on the full interval.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			n, err := db.SweepRetention(maxAge)
			if err != nil {
				logger.Printf("retention sweep error: %v", err)
			} else if n > 0 {
				logger.Printf("retention sweep flagged %d message(s) older than %s", n, maxAge)
			}
			timer.Reset(every)
		}
	}
}
