# Chatmail

Chatmail is a minimal local-domain mail server written in Go. It provides:

- SMTP submission on `127.0.0.1:1025`
- IMAP access on `127.0.0.1:1143`
- bbolt-backed user, mailbox, UID, flag, and message persistence
- Administrative CLI for user lifecycle operations
- Optional TLS exposure through stunnel for ports 465/587/993

The server is intentionally scoped to the `local.chat` domain. External relay is blocked and authenticated SMTP senders must use their own `@local.chat` identity.

## Repository layout

```text
cmd/chatmail/              Main SMTP + IMAP server process
cmd/chatmail-admin/        Administrative CLI
internal/database/         bbolt persistence layer and mailbox operations
internal/imap/             Minimal IMAP4rev1 server implementation
internal/smtp/             SMTP submission backend using go-smtp
generate_certs.sh          Development self-signed stunnel certificate helper
stunnel.conf               Example TLS wrapper configuration
systemd/chatmail.service   Example Linux service unit
```

## Build and test

This environment may not allow executing Go test binaries from `/tmp`, so set `GOTMPDIR` to a workspace path when running tests.

```bash
go build ./...
go vet ./...
mkdir -p /workspace/.tmp
GOTMPDIR=/workspace/.tmp go test -race -count=1 -timeout=120s ./...
go mod verify
```

## Run locally

```bash
go run ./cmd/chatmail
```

The daemon stores data under `/var/lib/chatmail`:

- `/var/lib/chatmail/chatmail.db` — bbolt database
- `/var/lib/chatmail/chatmail.log` — server log

## Administrative CLI

Build or run the admin command with a database path:

```bash
go run ./cmd/chatmail-admin -- list -db /var/lib/chatmail/chatmail.db
go run ./cmd/chatmail-admin -- create -u alice -p 'strong-password' -db /var/lib/chatmail/chatmail.db
go run ./cmd/chatmail-admin -- suspend -u alice -db /var/lib/chatmail/chatmail.db
go run ./cmd/chatmail-admin -- activate -u alice -db /var/lib/chatmail/chatmail.db
go run ./cmd/chatmail-admin -- status -u alice -db /var/lib/chatmail/chatmail.db
go run ./cmd/chatmail-admin -- logs -n 100 -logpath /var/lib/chatmail/chatmail.log
```

Usernames without a domain are normalized to `@local.chat` by the admin CLI.

## Security notes

- The Go SMTP and IMAP listeners bind only to loopback and are intended to sit behind stunnel or another TLS terminator.
- SMTP authentication is required before `MAIL FROM`, `RCPT TO`, or `DATA`.
- SMTP `MAIL FROM` must match the authenticated identity to prevent local sender spoofing.
- Recipient existence and suspension state are checked atomically before delivery.
- bbolt write transactions avoid expensive bcrypt work to reduce lock contention.
- Message payloads are bounded by the SMTP server's configured 10 MiB message limit.

## TLS/stunnel

Generate a development certificate:

```bash
./generate_certs.sh
```

For production, use a certificate from a trusted CA where possible. The included `stunnel.conf` is an example for exposing IMAPS and SMTP submission ports while forwarding to the loopback Go services.
