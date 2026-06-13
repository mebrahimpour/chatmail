package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"chatmail/internal/database"
)

func printHelp() {
	fmt.Println("Chatmail User Administrative CLI")
	fmt.Println("Usage: chatmail-admin <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  list                      List all registered users")
	fmt.Println("  create -u <e> -p <pw>     Register/Create a new user")
	fmt.Println("  password -u <e> -p <pw>   Reset/Change user password")
	fmt.Println("  suspend -u <e>            Suspend/Deactivate a user account")
	fmt.Println("  activate -u <e>           Activate/Unlock a user account")
	fmt.Println("  delete -u <e>             Delete a user and cascade message flags")
	fmt.Println("  status -u <e>             Show details and status of a user")
	fmt.Println("  logs                      Tail or view the chatmail server diagnostic logs")
	fmt.Println("\nOptions:")
	fmt.Println("  -u, -username             User email address")
	fmt.Println("  -p, -password             Plaintext password")
	fmt.Println("  -db                       Path to the chatmail bbolt database (default: /var/lib/chatmail/chatmail.db)")
	fmt.Println("  -f, -follow               With 'logs': Tail / follow log output dynamically (default: false)")
	fmt.Println("  -n, -lines                With 'logs': Number of recent lines to display (default: 50)")
	fmt.Println("  -logpath                  With 'logs': Custom path to the log file (default: /var/lib/chatmail/chatmail.log)")
}

func tailFile(filePath string, follow bool, lines int) error {
	if lines < 0 {
		return fmt.Errorf("line count must be non-negative")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read lines to print the tail buffer in a memory-bounded way.
	// Raise the scanner buffer to 1 MiB per line to handle long log entries
	// (e.g. base64-encoded content or stack traces) without returning
	// "bufio.Scanner: token too long".
	const maxLineBytes = 1 * 1024 * 1024
	var lastLines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, maxLineBytes), maxLineBytes)
	for scanner.Scan() {
		lastLines = append(lastLines, scanner.Text())
		if len(lastLines) > lines {
			lastLines = lastLines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Print historical log lines
	for _, l := range lastLines {
		fmt.Println(l)
	}

	if !follow {
		return nil
	}

	// Follow new writes sequentially
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if line != "" {
					fmt.Print(line)
				}
				time.Sleep(150 * time.Millisecond)
				continue
			}
			return err
		}
		fmt.Print(line)
	}
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	cmd := os.Args[1]

	// Setup CLI flags
	fs := flag.NewFlagSet("chatmail-admin", flag.ExitOnError)
	username := fs.String("u", "", "User email address")
	fs.StringVar(username, "username", "", "User email address")
	password := fs.String("p", "", "Plaintext password")
	fs.StringVar(password, "password", "", "Plaintext password")
	dbPath := fs.String("db", "/var/lib/chatmail/chatmail.db", "Path to bbolt database")

	// Log audit specific options
	follow := fs.Bool("f", false, "Follow log output dynamically")
	fs.BoolVar(follow, "follow", false, "Follow log output dynamically")
	lines := fs.Int("n", 50, "Number of recent lines to display")
	fs.IntVar(lines, "lines", 50, "Number of recent lines to display")
	logPath := fs.String("logpath", "/var/lib/chatmail/chatmail.log", "Path to log file")

	// Parse flags discarding the command name
	_ = fs.Parse(os.Args[2:])

	// Intercept stateless logs and help commands first to prevent unnecessary Bbolt lock contention
	switch cmd {
	case "help":
		printHelp()
		return

	case "logs":
		fmt.Printf("Auditing Server Logs (%s, follow=%v, lines=%d)...\n", *logPath, *follow, *lines)
		err := tailFile(*logPath, *follow, *lines)
		if err != nil {
			log.Fatalf("Audit error: %v", err)
		}
		return
	}

	// For administrative writes & query commands, map the transactional Bbolt DB
	readOnly := (cmd == "list" || cmd == "status")
	db, err := database.NewBboltDBWithOptions(*dbPath, readOnly)
	if err != nil {
		log.Fatalf("Fatal: Failed to map Bbolt Database from %s: %v", *dbPath, err)
	}
	defer db.Close()

	cleanedUser := ""
	if cmd != "list" {
		if *username == "" {
			log.Fatal("Error: -u (username/email) is required.")
		}
		var err error
		cleanedUser, err = cleanAdminAddress(*username)
		if err != nil {
			log.Fatalf("Input validation failed: %v", err)
		}
	}

	switch cmd {
	case "list":
		// ListUsersWithStatus reads both buckets in a single read transaction
		// instead of opening N separate transactions (one per IsUserSuspended call).
		users, err := db.ListUsersWithStatus()
		if err != nil {
			log.Fatalf("Error listing users: %v", err)
		}
		fmt.Printf("Registered Users (%d total):\n", len(users))
		for i, u := range users {
			statusStr := "Active"
			if u.Suspended {
				statusStr = "Suspended"
			}
			fmt.Printf("  %d. %s [%s]\n", i+1, u.Username, statusStr)
		}

	case "create":
		if *password == "" {
			log.Fatal("Error: -p (password) is required for 'create' command.")
		}
		err := db.CreateUser(cleanedUser, *password)
		if err != nil {
			log.Fatalf("Error creating user %s: %v", cleanedUser, err)
		}
		fmt.Printf("Success: User %s created and mailbox bootstrapped successfully.\n", cleanedUser)

	case "password":
		if *password == "" {
			log.Fatal("Error: -p (password) is required for 'password' command.")
		}
		err := db.SetUserPassword(cleanedUser, *password)
		if err != nil {
			log.Fatalf("Error resetting password for user %s: %v", cleanedUser, err)
		}
		fmt.Printf("Success: Password for user %s altered successfully.\n", cleanedUser)

	case "suspend":
		err := db.SuspendUser(cleanedUser)
		if err != nil {
			log.Fatalf("Error suspending user %s: %v", cleanedUser, err)
		}
		fmt.Printf("Success: User %s has been suspended. SMTP and IMAP access revoked.\n", cleanedUser)

	case "activate":
		err := db.ActivateUser(cleanedUser)
		if err != nil {
			log.Fatalf("Error activating user %s: %v", cleanedUser, err)
		}
		fmt.Printf("Success: User %s has been activated. SMTP and IMAP access restored.\n", cleanedUser)

	case "delete":
		err := db.DeleteUser(cleanedUser)
		if err != nil {
			log.Fatalf("Error deleting user %s: %v", cleanedUser, err)
		}
		fmt.Printf("Success: User %s deleted and cascading message flags updated to \\Deleted (0x08).\n", cleanedUser)

	case "status":
		// GetUserStatus reads both existence and suspension state in a single
		// atomic read transaction, eliminating the TOCTOU race that exists when
		// UserExists and IsUserSuspended are called as two sequential transactions.
		exists, suspended, err := db.GetUserStatus(cleanedUser)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if !exists {
			fmt.Printf("User %s does not exist in the database\n", cleanedUser)
			return
		}

		statusStr := "Active"
		if suspended {
			statusStr = "Suspended"
		}

		fmt.Printf("User Status Profile:\n")
		fmt.Printf("  Username/Email:  %s\n", cleanedUser)
		fmt.Printf("  Access Status:   %s\n", statusStr)

	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

func cleanAdminAddress(addr string) (string, error) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return "", fmt.Errorf("email address/username cannot be empty")
	}
	if strings.ContainsAny(addr, "\r\n\t ") {
		return "", fmt.Errorf("email address/username contains invalid whitespace")
	}
	if !strings.Contains(addr, "@") {
		addr = addr + "@local.chat"
	}
	if strings.Count(addr, "@") != 1 {
		return "", fmt.Errorf("email address %q is malformed", addr)
	}
	parts := strings.SplitN(addr, "@", 2)
	if parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("email address %q is malformed", addr)
	}
	if parts[1] != "local.chat" {
		return "", fmt.Errorf("email address %q does not match configured system domain 'local.chat'", addr)
	}
	return addr, nil
}
