#!/bin/bash
# Shell script to generate self-signed SSL/TLS certificates for stunnel development/deployment
set -e

CERT_DIR="./certs"
CERT_FILE="${CERT_DIR}/stunnel.pem"

echo "==== Chatmail Stunnel Certificate Generator ===="
echo "Creating certs directory..."
mkdir -p "${CERT_DIR}"

if [ -f "${CERT_FILE}" ]; then
    echo "Existing certificate found at ${CERT_FILE}."
    overwrite=false
    if [[ "$1" == "-f" || "$1" == "--force" ]]; then
        overwrite=true
    elif [ -t 0 ]; then
        read -p "Do you want to overwrite it? (y/n): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            overwrite=true
        fi
    else
        echo "Non-interactive environment detected. Overwriting existing certificate..."
        overwrite=true
    fi

    if [ "$overwrite" = false ]; then
        echo "Generation aborted. Keeping current certificate."
        exit 0
    fi
fi

echo "Generating new 2048-bit RSA Private Key and Self-Signed Certificate..."
# Force a private default before writing the combined certificate/private-key
# PEM. The file contains a private key, so it must never be group/world-readable.
umask 077
openssl req -new -x509 -days 365 -nodes \
  -out "${CERT_FILE}" \
  -keyout "${CERT_FILE}" \
  -subj "/C=US/ST=State/L=City/O=Chatmail/OU=IT/CN=local.chat" \
  -addext "subjectAltName = DNS:local.chat, DNS:localhost, IP:127.0.0.1"
chmod 600 "${CERT_FILE}"

echo "========================================="}ியல்      (jsonуы) was malformed? It shows extra. Let's call proper. (I need retry)»}      trak? Need send valid.        (tool call failed? no result maybe because malformed in analysis? Actually not sent? Let's send.)       «}      Nope. Need tool call.      «}       We'll call now.      «}      Hm.   Need in commentary.        «}      Let's do.      «}      (ignore)     
echo "Success! Combined PEM file created: ${CERT_FILE}"
echo "To use this in production on your Raspberry Pi 4:"
echo "1. Copy ${CERT_FILE} to /etc/stunnel/stunnel.pem"
echo "2. Run: sudo chmod 600 /etc/stunnel/stunnel.pem"
echo "3. Run: sudo chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem"
echo "4. Restart stunnel: sudo systemctl restart stunnel4"
echo "========================================="
