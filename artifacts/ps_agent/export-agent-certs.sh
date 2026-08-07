#!/usr/bin/env bash
set -euo pipefail

show_help() {
    cat << 'EOF'
export-agent-certs.sh — Export CA + agent certs as PEM/PFX files

Usage:
  ./export-agent-certs.sh [output-dir]
  ./export-agent-certs.sh -h

Options:
  output-dir    Directory to write cert files (default: ./certs)
  -h, --help    Show this help message

EOF
    exit 0
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && show_help

if [[ "$1" == *:* ]]; then
    OUTPUT_DIR="${3:-./certs}"
else
    OUTPUT_DIR="${1:-./certs}"
fi
STORAGE_PATH="$HOME/.ligolo-mp-server/storage/data.db"

if [ ! -f "$STORAGE_PATH" ]; then
    echo "[-] Server storage not found at $STORAGE_PATH"
    echo "[-] Run this script on the machine where the Ligolo-MP server is running."
    exit 1
fi

if ! command -v sqlite3 &>/dev/null; then
    echo "[-] sqlite3 is required. Install it first: apt install sqlite3"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "[-] python3 is required."
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo "[-] openssl is required."
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] Reading certs from $STORAGE_PATH ..."

CA_JSON=$(sqlite3 "$STORAGE_PATH" "SELECT value FROM certificates WHERE name='__CA'")

if [ -z "$CA_JSON" ]; then
    echo "[-] CA certificate not found in database."
    exit 1
fi

echo "[*] Exporting CA certificate ..."
echo "$CA_JSON" | python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
sys.stdout.buffer.write(base64.b64decode(d['Certificate']))
" > "$OUTPUT_DIR/ca.pem"

echo "$CA_JSON" | python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
pem = base64.b64decode(d['Key']).decode()
pem = pem.replace('ECDSA PRIVATE KEY', 'EC PRIVATE KEY')
sys.stdout.write(pem)
" > "$OUTPUT_DIR/ca.key"

echo "[+] CA certificate: $OUTPUT_DIR/ca.pem"

echo "[*] Generating fresh agent certificate ..."

openssl ecparam -name prime256v1 -genkey -noout -out "$OUTPUT_DIR/agent.key"
openssl req -new -key "$OUTPUT_DIR/agent.key" -subj "/CN=agent" -out /tmp/agent_export.csr 2>/dev/null
openssl x509 -req -in /tmp/agent_export.csr \
    -CA "$OUTPUT_DIR/ca.pem" -CAkey "$OUTPUT_DIR/ca.key" \
    -CAcreateserial -days 3650 \
    -extfile <(printf "extendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=IP:127.0.0.1") \
    -out "$OUTPUT_DIR/agent.pem" 2>/dev/null

rm -f /tmp/agent_export.csr "$OUTPUT_DIR/ca.key" "$OUTPUT_DIR/ca.srl"

echo "[*] Generating PFX bundle ..."
openssl pkcs12 -export \
    -in "$OUTPUT_DIR/agent.pem" \
    -inkey "$OUTPUT_DIR/agent.key" \
    -out "$OUTPUT_DIR/agent.pfx" \
    -passout pass: 2>/dev/null

echo "[+] Agent certificate: $OUTPUT_DIR/agent.pem"
echo "[+] Agent private key: $OUTPUT_DIR/agent.key"
echo "[+] PFX bundle:        $OUTPUT_DIR/agent.pfx"
echo ""
echo "[*] Done! Copy these files to the Windows target:"
echo "    $OUTPUT_DIR/ca.pem"
echo ""
echo "[*] PowerShell 7+:"
echo "    .\\agent.ps1 -Server 10.0.0.5:11601 -CACertFile ca.pem -CertFile agent.pem -KeyFile agent.key"
echo ""
echo "[*] PowerShell 5.1:"
echo "    .\\agent.ps1 -Server 10.0.0.5:11601 -CACertFile ca.pem -PfxFile agent.pfx"
