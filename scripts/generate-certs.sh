#!/bin/bash
# =============================================================================
# Generate Test Certificates for mTLS Demo
# =============================================================================
# This script generates all certificates needed to run the .NET mTLS demo.
# Uses OpenSSL directly (no Python dependencies needed).
#
# What it creates:
#   certs/
#   ├── ca.key          Root CA private key
#   ├── ca.crt          Root CA certificate
#   ├── server.key      Server private key
#   ├── server.crt      Server certificate (signed by CA)
#   ├── server.pfx      Server cert + key in PKCS#12 format (.NET)
#   ├── client.key      Client/device private key
#   ├── client.crt      Client/device certificate (signed by CA)
#   └── client.pfx      Client cert + key in PKCS#12 format (.NET)
#
# Usage:
#   chmod +x generate-certs.sh
#   ./generate-certs.sh

set -euo pipefail

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Generating mTLS Test Certificates                       ║"
echo "║  Output: $CERTS_DIR"
echo "╚══════════════════════════════════════════════════════════╝"

# =============================================================================
# 1. Root CA
# =============================================================================
echo ""
echo "── Generating Root CA ──"

# Generate ECDSA P-256 private key for CA
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
chmod 600 ca.key

# Create self-signed root CA certificate
openssl req -new -x509 -key ca.key -out ca.crt \
  -days 3650 \
  -subj "/CN=Test Root CA/O=Test Organization" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -addext "subjectKeyIdentifier=hash"

echo "  CA Subject: $(openssl x509 -in ca.crt -subject -noout)"
echo "  CA Validity: $(openssl x509 -in ca.crt -dates -noout | tr '\n' ' ')"
echo "  ✓ Root CA generated"

# =============================================================================
# 2. Server Certificate
# =============================================================================
echo ""
echo "── Generating Server Certificate ──"

# Generate server key
openssl ecparam -genkey -name prime256v1 -noout -out server.key
chmod 600 server.key

# Create server CSR
openssl req -new -key server.key -out server.csr \
  -subj "/CN=localhost/O=Test Organization"

# Create extension file for server cert
cat > server.ext << 'EXTEOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:localhost, DNS:host.docker.internal, IP:127.0.0.1, IP:0.0.0.0
authorityKeyIdentifier = keyid,issuer
EXTEOF

# Sign server cert with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt \
  -days 730 \
  -extfile server.ext

# Create PFX for .NET
openssl pkcs12 -export -out server.pfx \
  -inkey server.key -in server.crt -certfile ca.crt \
  -passout pass:server123

echo "  Server Subject: $(openssl x509 -in server.crt -subject -noout)"
echo "  Server SANs: $(openssl x509 -in server.crt -ext subjectAltName -noout 2>/dev/null || echo 'N/A')"
echo "  Server PFX password: server123"
echo "  ✓ Server certificate generated"

# =============================================================================
# 3. Client Certificate (Device)
# =============================================================================
echo ""
echo "── Generating Client Certificate (Device) ──"

# Generate client key
openssl ecparam -genkey -name prime256v1 -noout -out client.key
chmod 600 client.key

# Create client CSR
openssl req -new -key client.key -out client.csr \
  -subj "/CN=device-042/OU=IoT-Sensors/O=Test Organization/serialNumber=SN-2025-00042"

# Create extension file for client cert
cat > client.ext << 'EXTEOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://cluster.local/ns/default/device-042, DNS:device-042.iot.local
authorityKeyIdentifier = keyid,issuer
EXTEOF

# Sign client cert with CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt \
  -days 730 \
  -extfile client.ext

# Create PFX for .NET
openssl pkcs12 -export -out client.pfx \
  -inkey client.key -in client.crt -certfile ca.crt \
  -passout pass:client123

echo "  Client Subject: $(openssl x509 -in client.crt -subject -noout)"
echo "  Client SANs: $(openssl x509 -in client.crt -ext subjectAltName -noout 2>/dev/null || echo 'N/A')"
echo "  Client PFX password: client123"
echo "  ✓ Client certificate generated"

# =============================================================================
# Cleanup temporary files
# =============================================================================
rm -f server.csr server.ext client.csr client.ext ca.srl

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "Generated Files:"
echo "═══════════════════════════════════════════════════════════"
ls -la "$CERTS_DIR"/*.{crt,key,pfx} 2>/dev/null | awk '{printf "  %-20s %s bytes\n", $NF, $5}'

echo ""
echo "Quick verification:"
echo "  openssl x509 -in $CERTS_DIR/server.crt -text -noout"
echo "  openssl x509 -in $CERTS_DIR/client.crt -text -noout"
echo ""
echo "Test mTLS with curl:"
echo "  curl --cacert $CERTS_DIR/ca.crt \\"
echo "       --cert $CERTS_DIR/client.crt \\"
echo "       --key $CERTS_DIR/client.key \\"
echo "       https://localhost:5001/api/device-info"
echo ""
echo "Verify certificate chain:"
echo "  openssl verify -CAfile $CERTS_DIR/ca.crt $CERTS_DIR/server.crt"
echo "  openssl verify -CAfile $CERTS_DIR/ca.crt $CERTS_DIR/client.crt"
