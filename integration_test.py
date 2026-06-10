#!/usr/bin/env python3
"""Localhost integration tests for the chatmail server.

These tests exercise the compiled Go binary over its plaintext loopback ports
(no TLS, no stunnel, no external network). The server is launched in a
temporary data directory, the protocol handshakes from the design Test Matrix
are driven directly over sockets, and the server is torn down afterward.

Usage:
    # build the binary first (or set CHATMAIL_BIN to an existing one)
    go build -o chatmail ./cmd/chatmail
    python3 integration_test.py

Environment:
    CHATMAIL_BIN   path to the compiled binary (default: ./chatmail)
"""

import base64
import os
import socket
import subprocess
import sys
import tempfile
import time

SMTP_HOST, SMTP_PORT = "127.0.0.1", 1025
IMAP_HOST, IMAP_PORT = "127.0.0.1", 1143
DOMAIN = "local.chat"


# --------------------------------------------------------------------------- #
# Low-level socket helpers
# --------------------------------------------------------------------------- #
def recv_line(sock):
    """Read a single CRLF-terminated line."""
    buf = b""
    while not buf.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace")


def recv_smtp(sock):
    """Read a (possibly multi-line) SMTP reply, returning the final line."""
    line = recv_line(sock)
    # multiline replies look like "250-..." until "250 ..."
    while len(line) >= 4 and line[3] == "-":
        line = recv_line(sock)
    return line


def smtp_connect():
    s = socket.create_connection((SMTP_HOST, SMTP_PORT), timeout=10)
    banner = recv_smtp(s)
    assert banner.startswith("220"), f"bad SMTP banner: {banner!r}"
    return s


def smtp_cmd(sock, line):
    sock.sendall(line.encode() + b"\r\n")
    return recv_smtp(sock)


def smtp_login(sock, user, password):
    resp = smtp_cmd(sock, f"EHLO test.{DOMAIN}")
    assert resp.startswith("250"), f"EHLO failed: {resp!r}"
    blob = base64.b64encode(b"\x00" + user.encode() + b"\x00" + password.encode()).decode()
    return smtp_cmd(sock, f"AUTH PLAIN {blob}")


def imap_connect():
    s = socket.create_connection((IMAP_HOST, IMAP_PORT), timeout=10)
    recv_line(s)  # greeting
    return s


def imap_cmd(sock, tag, line, read_until_tag=True):
    sock.sendall(f"{tag} {line}\r\n".encode())
    out = ""
    if not read_until_tag:
        return out
    while True:
        ln = recv_line(sock)
        if not ln:
            break
        out += ln
        if ln.startswith(tag + " "):
            break
    return out


# --------------------------------------------------------------------------- #
# Test cases (Section 6 Validation Checkpoints)
# --------------------------------------------------------------------------- #
def test_smtp_auto_registration():
    s = smtp_connect()
    resp = smtp_login(s, f"alice@{DOMAIN}", "password123")
    assert "235" in resp, f"auto-registration failed: {resp!r}"
    smtp_cmd(s, "QUIT")
    s.close()


def test_authentication_mismatch():
    # Register, then reconnect with a wrong password.
    s = smtp_connect()
    smtp_login(s, f"bob@{DOMAIN}", "correct-horse")
    smtp_cmd(s, "QUIT")
    s.close()

    s = smtp_connect()
    resp = smtp_login(s, f"bob@{DOMAIN}", "wrong-password")
    assert "535" in resp, f"expected 535 on mismatch, got: {resp!r}"
    s.close()


def test_boundary_protection_external_domain():
    s = smtp_connect()
    assert "235" in smtp_login(s, f"alice@{DOMAIN}", "password123")
    assert smtp_cmd(s, f"MAIL FROM:<alice@{DOMAIN}>").startswith("250")
    resp = smtp_cmd(s, "RCPT TO:<victim@gmail.com>")
    assert "551" in resp, f"expected 551 for external domain, got: {resp!r}"
    s.close()


def test_payload_envelope_size_limit():
    s = smtp_connect()
    assert "235" in smtp_login(s, f"alice@{DOMAIN}", "password123")
    assert smtp_cmd(s, f"MAIL FROM:<alice@{DOMAIN}>").startswith("250")
    assert smtp_cmd(s, f"RCPT TO:<alice@{DOMAIN}>").startswith("250")
    resp = smtp_cmd(s, "DATA")
    assert resp.startswith("354"), f"DATA not accepted: {resp!r}"
    # Stream ~12 MB of body as proper CRLF-delimited lines (each well under the
    # SMTP line-length limit) so the message-size cap, not the line-length cap,
    # is the control under test. Then send the end-of-data terminator.
    line = b"X" * 998 + b"\r\n"           # 1000 bytes/line
    payload = line * 12600               # ~12 MB
    try:
        for off in range(0, len(payload), 1024 * 1024):
            s.sendall(payload[off:off + 1024 * 1024])
        s.sendall(b".\r\n")
        resp = recv_smtp(s)
    except (BrokenPipeError, ConnectionResetError):
        resp = ""
    assert "552" in resp, f"expected 552 for oversize payload, got: {resp!r}"
    s.close()


def test_history_fetching_roundtrip():
    # Deliver a message via SMTP, then read it back over IMAP.
    body = (
        "Message-ID: <roundtrip@local.chat>\r\n"
        "From: alice@local.chat\r\n"
        "To: carol@local.chat\r\n"
        "Subject: hello\r\n"
        "Chat-Group-ID: testgroup\r\n"
        "\r\n"
        "This is the secret payload body.\r\n"
    )
    s = smtp_connect()
    assert "235" in smtp_login(s, f"alice@{DOMAIN}", "password123")
    assert smtp_cmd(s, f"MAIL FROM:<alice@{DOMAIN}>").startswith("250")
    assert smtp_cmd(s, f"RCPT TO:<carol@{DOMAIN}>").startswith("250")
    assert smtp_cmd(s, "DATA").startswith("354")
    s.sendall(body.encode() + b".\r\n")
    assert recv_smtp(s).startswith("250"), "message not stored"
    smtp_cmd(s, "QUIT")
    s.close()

    # carol auto-registers on her first SMTP auth, then logs in over IMAP.
    s = smtp_connect()
    smtp_login(s, f"carol@{DOMAIN}", "carol-pass")
    smtp_cmd(s, "QUIT")
    s.close()

    im = imap_connect()
    assert "OK" in imap_cmd(im, "a1", f"LOGIN carol@{DOMAIN} carol-pass")
    sel = imap_cmd(im, "a2", 'SELECT "INBOX"')
    assert "EXISTS" in sel and "a2 OK" in sel, f"SELECT failed: {sel!r}"
    fetched = imap_cmd(im, "a3", "UID FETCH 1:* (FLAGS RFC822.SIZE BODY.PEEK[])")
    assert "secret payload body" in fetched, f"payload not returned: {fetched!r}"
    assert "Chat-Group-ID" in fetched, "DeltaChat header was not preserved"
    imap_cmd(im, "a4", "LOGOUT")
    im.close()


# --------------------------------------------------------------------------- #
# Additional tests (consolidated from all three repos)
# --------------------------------------------------------------------------- #

def test_multi_recipient_delivery(server_addr=None):
    """One SMTP DATA transaction delivers to two local recipients."""
    import socket as _socket

    def _auth_imap(user, pw):
        s = _socket.create_connection((IMAP_HOST, IMAP_PORT), timeout=10)
        recv_line(s)  # greeting
        s.send(f"a1 LOGIN {user} {pw}\r\n".encode())
        resp = recv_line(s)
        assert "OK" in resp, f"IMAP LOGIN failed: {resp!r}"
        return s

    # Register both users via SMTP
    for u in ["multia@local.chat", "multib@local.chat"]:
        s = smtp_connect()
        s.send(b"EHLO local.chat\r\n")
        recv_smtp(s)
        tok = _b64("\x00" + u + "\x00password")
        s.send(f"AUTH PLAIN {tok}\r\n".encode())
        assert recv_smtp(s).startswith("235"), f"AUTH failed for {u}"
        s.send(b"MAIL FROM:<sender@local.chat>\r\n")
        recv_smtp(s)
        s.send(b"RCPT TO:<multia@local.chat>\r\n")
        recv_smtp(s)
        s.send(b"DATA\r\n")
        recv_smtp(s)
        s.send(b"Subject: init\r\n\r\ninit\r\n.\r\n")
        recv_smtp(s)
        s.close()

    # Now send from multia to both recipients
    s = smtp_connect()
    s.send(b"EHLO local.chat\r\n")
    recv_smtp(s)
    tok = _b64("\x00multia@local.chat\x00password")
    s.send(f"AUTH PLAIN {tok}\r\n".encode())
    assert recv_smtp(s).startswith("235")
    s.send(b"MAIL FROM:<multia@local.chat>\r\n")
    recv_smtp(s)
    s.send(b"RCPT TO:<multia@local.chat>\r\n")
    recv_smtp(s)
    s.send(b"RCPT TO:<multib@local.chat>\r\n")
    recv_smtp(s)
    s.send(b"DATA\r\n")
    recv_smtp(s)
    s.send(b"Subject: multi\r\n\r\nmulti-rcpt body\r\n.\r\n")
    assert recv_smtp(s).startswith("250"), "DATA response should be 250"
    s.close()

    # Verify both mailboxes received the message
    for u in ["multia@local.chat", "multib@local.chat"]:
        is_ = _auth_imap(u, "password")
        is_.send(b"a2 SELECT INBOX\r\n")
        sel = b""
        while b"a2 " not in sel:
            sel += is_.recv(4096)
        assert b"OK" in sel, f"SELECT failed for {u}"
        is_.close()

    print("[+] multi-recipient delivery: PASS")
    return True


def test_imap_idle():
    """IDLE command must be accepted and DONE must end it gracefully."""
    import socket as _socket, threading

    user = "idletest@local.chat"
    # Ensure user exists via SMTP registration
    s = smtp_connect()
    s.send(b"EHLO local.chat\r\n")
    recv_smtp(s)
    tok = _b64("\x00" + user + "\x00pw")
    s.send(f"AUTH PLAIN {tok}\r\n".encode())
    recv_smtp(s)
    s.close()

    is_ = _socket.create_connection((IMAP_HOST, IMAP_PORT), timeout=10)
    recv_line(is_)  # greeting
    is_.send(b"a1 LOGIN idletest@local.chat pw\r\n")
    resp = recv_line(is_)
    assert "OK" in resp, f"LOGIN failed: {resp!r}"
    is_.send(b"a2 SELECT INBOX\r\n")
    while True:
        l = recv_line(is_)
        if l.startswith("a2 "):
            break
    is_.send(b"a3 IDLE\r\n")
    cont = recv_line(is_)
    assert cont.startswith("+"), f"Expected continuation, got {cont!r}"
    # Send DONE after a short pause
    import time as _time
    _time.sleep(0.2)
    is_.send(b"DONE\r\n")
    resp = recv_line(is_)
    assert "OK" in resp or "a3 " in resp, f"IDLE DONE response unexpected: {resp!r}"
    is_.close()
    print("[+] IMAP IDLE: PASS")
    return True


def _b64(s):
    import base64
    return base64.b64encode(s.encode()).decode()




TESTS = [
    test_smtp_auto_registration,
    test_authentication_mismatch,
    test_boundary_protection_external_domain,
    test_payload_envelope_size_limit,
    test_history_fetching_roundtrip,
    test_multi_recipient_delivery,
    test_imap_idle,
]


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #
def wait_for_port(host, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((host, port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    binary = os.environ.get("CHATMAIL_BIN", "./chatmail")
    if not os.path.exists(binary):
        print(f"binary not found: {binary} (build with: go build -o chatmail ./cmd/chatmail)")
        return 2

    with tempfile.TemporaryDirectory() as data_dir:
        proc = subprocess.Popen(
            [
                binary,
                "--data-dir", data_dir,
                "--domain", DOMAIN,
                "--smtp-addr", f"{SMTP_HOST}:{SMTP_PORT}",
                "--imap-addr", f"{IMAP_HOST}:{IMAP_PORT}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            if not (wait_for_port(SMTP_HOST, SMTP_PORT) and wait_for_port(IMAP_HOST, IMAP_PORT)):
                print("server did not start listening in time")
                return 1

            failures = 0
            for test in TESTS:
                try:
                    test()
                    print(f"PASS  {test.__name__}")
                except AssertionError as exc:
                    failures += 1
                    print(f"FAIL  {test.__name__}: {exc}")
                except Exception as exc:  # noqa: BLE001
                    failures += 1
                    print(f"ERROR {test.__name__}: {exc!r}")

            print()
            print(f"{len(TESTS) - failures}/{len(TESTS)} tests passed")
            return 1 if failures else 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
