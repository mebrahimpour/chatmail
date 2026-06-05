# chatmail

A minimal [chatmail](https://chatmail.at/) server (SMTP + IMAP) for
[DeltaChat](https://delta.chat/), written in Go and designed for **fewer than 50
users on an isolated, air-gapped network**.

The Go binary speaks **plaintext only** on the loopback interface. TLS is
terminated externally by [`stunnel4`](https://www.stunnel.org/), which forwards
the decrypted byte stream to the application. All state lives in a single
[bbolt](https://github.com/etcd-io/bbolt) file.

```
[DeltaChat] --TLS 587/993--> [stunnel4] --plaintext 1025/1143--> [chatmail] <--> [bbolt file]
```

## Features

- **SMTP engine** (`127.0.0.1:1025`): auto-registers an account on first
  `AUTH PLAIN` (bcrypt-hashed), then verifies on subsequent logins. Enforces a
  single local domain (`local.chat`) on both `MAIL FROM` and `RCPT TO`, rejects
  external relay, caps messages at 10 MiB, and stores the raw MIME payload
  verbatim.
- **IMAP engine** (`127.0.0.1:1143`): `CAPABILITY`, `LOGIN`, `SELECT INBOX`,
  `UID FETCH`, `UID STORE`, `EXPUNGE`. A single `INBOX`; all reads/writes go
  through bbolt.
- **DeltaChat-safe storage**: message bodies and headers (`Autocrypt`,
  `Chat-Group-*`, `Message-ID`, OpenPGP signatures) are never modified. UIDs are
  never reused or rewound; `UIDVALIDITY` is generated once and never changes.
- **Retention loop**: a background sweep flags messages older than 30 days with
  `\Deleted` so they are reclaimed on the next `EXPUNGE`.

## Layout

```
cmd/chatmail/main.go         bootstrap: open db, start listeners, retention loop, signals
internal/database/bbolt.go   bucket hierarchy, transactions, binary serialization
internal/smtp/server.go      SMTP engine (emersion/go-smtp)
internal/imap/server.go      IMAP engine (emersion/go-imap/v2)
integration_test.py          localhost protocol tests (no external deps)
deploy/chatmail.service      systemd unit with the hardened sandbox profile
deploy/stunnel.conf          stunnel4 TLS-termination config
```

## Build & run

```sh
go build -o chatmail ./cmd/chatmail
./chatmail --domain local.chat --data-dir ./data \
    --smtp-addr 127.0.0.1:1025 --imap-addr 127.0.0.1:1143
```

Flags (all optional, defaults shown):

| Flag               | Default                        |
|--------------------|--------------------------------|
| `--domain`         | `local.chat`                   |
| `--data-dir`       | `/var/lib/chatmail`            |
| `--smtp-addr`      | `127.0.0.1:1025`               |
| `--imap-addr`      | `127.0.0.1:1143`               |
| `--retention`      | `720h` (30 days)               |
| `--sweep-interval` | `24h`                          |

## Tests

```sh
go test ./...                 # Go unit tests (storage layer)
go build -o chatmail ./cmd/chatmail && python3 integration_test.py
```

The integration suite covers the design's Validation Checkpoints: SMTP
auto-registration, password-mismatch rejection (`535`), external-domain
rejection (`551`), the 10 MiB size cap (`552`), and an IMAP `UID FETCH`
round-trip that verifies the stored payload is byte-identical.

## Deployment (DietPi / Debian 12)

1. Install the binary at `/usr/local/bin/chatmail` and create the service user:
   ```sh
   sudo useradd --system --no-create-home chatmail
   sudo install -m755 chatmail /usr/local/bin/chatmail
   ```
2. Install the systemd unit and start it:
   ```sh
   sudo cp deploy/chatmail.service /etc/systemd/system/
   sudo systemctl enable --now chatmail
   ```
3. Generate a self-signed cert and configure stunnel4 (see comments in
   `deploy/stunnel.conf`), then point DeltaChat at ports 587 (SMTP) and 993
   (IMAP) with the host's certificate.
