# 01 - TLS Fundamentals & How Let's Encrypt Works

## Table of Contents
- [Asymmetric Cryptography Primer](#asymmetric-cryptography-primer)
- [What Is a Certificate](#what-is-a-certificate)
- [Certificate Chain of Trust](#certificate-chain-of-trust)
- [TLS Handshake (One-Way)](#tls-handshake-one-way)
- [How Let's Encrypt Issues Certificates](#how-lets-encrypt-issues-certificates)
- [ACME Protocol Deep Dive](#acme-protocol-deep-dive)
- [Certificate Lifecycle](#certificate-lifecycle)

---

## Asymmetric Cryptography Primer

Before certificates make sense, you need to understand **public-key cryptography**.

```
  Key Generation
  ==============

  Algorithm (RSA-2048 / ECDSA P-256)
         |
         v
  +-------------+      +-------------+
  | Private Key |      | Public Key  |
  | (secret)    |      | (shareable) |
  +-------------+      +-------------+
        |                     |
        v                     v
   Sign / Decrypt       Verify / Encrypt
```

**Core Properties:**
- Data encrypted with the **public key** can only be decrypted with the **private key**
- Data signed with the **private key** can be verified by anyone with the **public key**
- You **cannot** derive the private key from the public key (computationally infeasible)

### RSA vs ECDSA (What Let's Encrypt Supports)

| Property      | RSA-2048          | ECDSA P-256        |
|---------------|-------------------|--------------------|
| Key Size      | 2048 bits         | 256 bits           |
| Signature Size| ~256 bytes        | ~64 bytes          |
| Performance   | Slower            | Faster             |
| Security      | ~112-bit          | ~128-bit           |
| Adoption      | Universal         | Growing            |

> **Staff Engineer Note:** For new services, prefer ECDSA P-256. Smaller keys, faster
> handshakes, less bandwidth. Let's Encrypt supports both.

---

## What Is a Certificate

An **X.509 certificate** is a signed document that binds a **public key** to an **identity**.

Think of it like a digitally signed ID card:

```
+------------------------------------------------------------------+
|                     X.509 v3 Certificate                         |
+------------------------------------------------------------------+
| Version:             3 (0x2)                                     |
| Serial Number:       04:E3:A2:...  (unique per CA)              |
| Signature Algorithm: sha256WithRSAEncryption                     |
|                                                                  |
| Issuer:              CN=R3, O=Let's Encrypt, C=US               |
|                   (who signed this cert)                         |
|                                                                  |
| Validity:                                                        |
|   Not Before:        Jan 15 00:00:00 2025 UTC                   |
|   Not After:         Apr 15 23:59:59 2025 UTC                   |
|                   (Let's Encrypt = 90-day certs)                 |
|                                                                  |
| Subject:             CN=api.example.com                          |
|                   (who this cert identifies)                     |
|                                                                  |
| Subject Public Key:  (the public key being certified)            |
|   Algorithm:         id-ecPublicKey (P-256)                      |
|   Public Key:        04:A1:B2:C3:...                             |
|                                                                  |
| Extensions (v3):                                                 |
|   Subject Alt Names: DNS:api.example.com, DNS:*.example.com     |
|   Key Usage:         Digital Signature, Key Encipherment         |
|   Extended Key Usage: TLS Web Server Auth                        |
|   Basic Constraints: CA:FALSE                                    |
|   Authority Key ID:  14:2E:B3:...                                |
|   Subject Key ID:    7A:3B:1C:...                                |
|   CRL Distribution:  http://r3.o.lencr.org                      |
|   OCSP:              http://r3.o.lencr.org                       |
|   CT Precert SCTs:   (Certificate Transparency timestamps)       |
+------------------------------------------------------------------+
|                                                                  |
| Signature:           (CA's digital signature over all above)     |
|   a3:b4:c5:d6:...                                               |
+------------------------------------------------------------------+
```

### Certificate Encoding Formats

```
PEM (.pem, .crt, .cer)          DER (.der, .cer)           PFX/PKCS#12 (.pfx, .p12)
========================         ================           =========================
Base64 encoded                   Binary encoded             Binary container
Human-readable                   Not human-readable         Contains cert + private key
-----BEGIN CERTIFICATE-----      Raw bytes                  Password protected
MIIFjTCCA3Wg...                                             Used by .NET / Windows
-----END CERTIFICATE-----
```

> **For .NET projects:** You'll mostly work with `.pfx` (PKCS#12) files or the
> `X509Certificate2` class which can load PEM, DER, or PFX.

---

## Certificate Chain of Trust

Certificates form a **chain** from your leaf certificate up to a trusted root.

```
  Trust Hierarchy
  ===============

  +---------------------------+
  | Root CA                   |  <-- Self-signed, pre-installed in OS/browser
  | CN=ISRG Root X1          |      trust stores. ~150 root CAs globally.
  | Validity: 2015 - 2035    |
  | Key: RSA 4096            |
  +-------------|-------------+
                | signs
                v
  +---------------------------+
  | Intermediate CA           |  <-- Signed by Root CA. Let's Encrypt uses
  | CN=R3                     |      intermediates so the root key stays offline.
  | Validity: 2020 - 2025    |
  | Key: RSA 2048            |
  +-------------|-------------+
                | signs
                v
  +---------------------------+
  | Leaf / End-Entity Cert    |  <-- YOUR certificate. Signed by Intermediate.
  | CN=api.example.com        |      This is what your server presents.
  | Validity: 90 days         |
  | Key: ECDSA P-256          |
  +---------------------------+
```

**Verification Process (what a TLS client does):**

1. Server presents `[leaf cert] + [intermediate cert]`
2. Client checks: Is leaf cert signed by intermediate? (verify signature using intermediate's public key)
3. Client checks: Is intermediate signed by a trusted root? (verify using root's public key from trust store)
4. Client checks: Are all certs within their validity period?
5. Client checks: Is the cert revoked? (CRL or OCSP check)
6. Client checks: Does the Subject Alternative Name (SAN) match the hostname?

> **Why 90-day certs?** Let's Encrypt intentionally uses short-lived certs to:
> - Reduce exposure window if a private key is compromised
> - Force automation of renewal (manual processes are error-prone)
> - Limit damage from mis-issuance

---

## TLS Handshake (One-Way)

Standard TLS (what happens when you visit `https://` sites):

```
  Client (Browser)                          Server (api.example.com)
  ================                          ========================

  1. ClientHello --------------------------->
     - TLS version (1.2/1.3)
     - Supported cipher suites
     - Client random (32 bytes)
     - SNI: api.example.com

                                            2. ServerHello
                                  <-----------  - Selected cipher suite
                                               - Server random
                                               - Certificate chain
                                               - (TLS 1.3: KeyShare)

  3. Verify certificate chain
     - Check signatures up to root
     - Check validity dates
     - Check SAN matches hostname
     - Check revocation (OCSP)

  4. Key Exchange
     - (RSA: encrypt pre-master
        secret with server's
        public key)
     - (ECDHE: Diffie-Hellman
        key agreement)

  5. Both sides derive session keys
     from the shared secret

  6. [Encrypted Application Data] <========> [Encrypted Application Data]
     (symmetric encryption: AES-GCM)
```

**Key insight:** In standard TLS, only the **server** proves its identity.
The client is anonymous. This is fine for browsers, but not for device-to-service auth.

---

## How Let's Encrypt Issues Certificates

Let's Encrypt is a **free, automated, open** Certificate Authority (CA) run by the
Internet Security Research Group (ISRG).

### The ACME Protocol

ACME = **A**utomatic **C**ertificate **M**anagement **E**nvironment (RFC 8555)

```
  Your Server                   ACME Client              Let's Encrypt
  (runs your app)               (certbot/acme.sh)        (ACME Server)
  ===============               =================        ==============

  1. You want a cert for api.example.com

                                2. Create account ------->
                                   (one-time, RSA key)    3. Account registered
                                                     <---    (account URL)

                                4. New order ------------>
                                   "I want a cert for     5. Here are your
                                    api.example.com"  <---    challenges

                                6. Challenge options:
                                   - HTTP-01 (port 80)
                                   - DNS-01 (TXT record)
                                   - TLS-ALPN-01 (port 443)

  === HTTP-01 Challenge Flow (most common) ===

                                7. Place token file
  8. Serve token at             <--- at well-known path
  http://api.example.com/
  .well-known/acme-challenge/
  <token>
                                9. "Ready" --------------->
                                                           10. Let's Encrypt
                                                               fetches the URL
                                                               from MULTIPLE
                                                               vantage points
  11. Serve token content ---------------------------------->
                                                           12. Validates!
                                                               Domain verified.

                                13. Submit CSR ----------->
                                    (Certificate Signing   14. Signs certificate
                                     Request with YOUR <---    Returns cert chain
                                     public key)

                                15. Install cert + key
  16. Server now uses      <--- on your server
      the new cert
```

### Challenge Types Explained

| Challenge | How It Works | Best For |
|-----------|-------------|----------|
| **HTTP-01** | Place a file at `/.well-known/acme-challenge/<token>` on port 80 | Web servers with port 80 access |
| **DNS-01** | Create a `_acme-challenge.example.com` TXT record | Wildcards (`*.example.com`), servers without port 80 |
| **TLS-ALPN-01** | Respond on port 443 with a special self-signed cert | When only port 443 is available |

> **DNS-01 is the only way to get wildcard certificates** from Let's Encrypt.
> This is important for Kubernetes ingress scenarios.

### What's in a CSR (Certificate Signing Request)?

```
+------------------------------------------+
| Certificate Signing Request (CSR)        |
+------------------------------------------+
| Subject:  CN=api.example.com             |
| Public Key: (YOUR public key)            |
| Extensions:                              |
|   SAN: api.example.com, *.example.com    |
+------------------------------------------+
| Signed with: YOUR private key            |
| (proves you own the private key          |
|  matching the public key in the CSR)     |
+------------------------------------------+
```

**Critical:** The private key **never leaves your server**. The CA only sees your public key.

---

## Certificate Lifecycle

```
  Generate Key Pair     Create CSR        Domain           CA Signs        Install
  (on your server)      (include          Validation       Certificate     Cert + Key
                         public key)      (ACME challenge)                 on Server
       |                    |                 |                |              |
       v                    v                 v                v              v
  [Day 0]              [Day 0]           [Day 0]          [Day 0]        [Day 0]
                                                                            |
       Cert valid for 90 days (Let's Encrypt)                               |
       |                                                                    |
       |    Renew at day 60 (30 days before expiry)                         |
       |    Most ACME clients auto-renew                                    |
       v                                                                    v
  [Day 60] ---- Auto-renewal triggered ---- New cert issued ---- Replaced [Day 60]
       |
       |    Old cert still valid until Day 90
       |    (grace period if renewal fails)
       v
  [Day 90] ---- Old cert expires
```

### Revocation

If your private key is compromised:

```
  You                     Let's Encrypt              Clients
  ===                     ==============             =======

  1. Revoke request --->  2. Mark as revoked
     (signed with            in CRL and OCSP
      account key            responder
      or cert key)
                                                    3. Clients check OCSP/CRL
                                                       before trusting cert
                                                       (OCSP stapling preferred)
```

**OCSP Stapling:** Server periodically fetches its own OCSP response from the CA
and "staples" it to the TLS handshake. This way clients don't need to contact the
CA directly (better privacy, faster handshake).

---

## Practical: Creating a Let's Encrypt Cert with Certbot

```bash
# Install certbot
sudo apt-get install certbot

# HTTP-01 challenge (standalone mode - certbot runs its own web server)
sudo certbot certonly --standalone -d api.example.com

# DNS-01 challenge (for wildcards)
sudo certbot certonly --manual --preferred-challenges dns -d "*.example.com"

# Where certs are stored:
# /etc/letsencrypt/live/api.example.com/
#   fullchain.pem   -> leaf cert + intermediate (send this to clients)
#   chain.pem       -> intermediate cert only
#   cert.pem        -> leaf cert only
#   privkey.pem     -> private key (GUARD THIS)

# Auto-renewal (add to cron or systemd timer)
sudo certbot renew --quiet

# Convert to PFX for .NET
openssl pkcs12 -export \
  -out api.example.com.pfx \
  -inkey privkey.pem \
  -in fullchain.pem \
  -password pass:YourSecurePassword
```

---

## Key Takeaways

1. **Certificates bind identity to a public key**, signed by a trusted CA
2. **Let's Encrypt automates** issuance via the ACME protocol (prove domain control, get cert)
3. **Private keys never leave your server** - only the CSR (with public key) goes to the CA
4. **90-day certs force automation** - this is a feature, not a limitation
5. **Chain of trust** = Leaf -> Intermediate -> Root (clients verify the whole chain)
6. **Standard TLS only authenticates the server** - for device auth, you need mTLS (next doc)

---

Next: [02 - Certificate Metadata Deep Dive](./02-certificate-metadata-deepdive.md)
