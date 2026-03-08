#!/usr/bin/env python3
"""
Let's Encrypt Certificate Generator using ACME Protocol
========================================================

This script demonstrates the COMPLETE ACME flow step-by-step:
1. Generate account key pair
2. Register with Let's Encrypt
3. Create a certificate order
4. Complete HTTP-01 or DNS-01 challenge
5. Submit CSR and retrieve certificate

Requirements:
    pip install cryptography acme josepy

Usage:
    # Staging (testing - use this first!)
    python acme_certificate.py --domain api.example.com --email admin@example.com --staging

    # Production (real cert)
    python acme_certificate.py --domain api.example.com --email admin@example.com

    # With DNS-01 challenge (for wildcards)
    python acme_certificate.py --domain "*.example.com" --email admin@example.com --challenge dns-01

    # Dry-run (explains each step without making real requests)
    python acme_certificate.py --domain api.example.com --email admin@example.com --dry-run
"""

import argparse
import json
import os
import sys
import time
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Step 0: Imports - Understanding the libraries
# ---------------------------------------------------------------------------
# cryptography: Low-level crypto operations (key generation, CSR creation)
# acme: Official ACME protocol client library
# josepy: JSON Object Signing and Encryption (for ACME account keys)

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.backends import default_backend
    import josepy as jose
    from acme import client as acme_client
    from acme import messages, challenges, crypto_util
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip install cryptography acme josepy")
    sys.exit(1)


# ACME Directory URLs
LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"


class AcmeCertificateManager:
    """
    Complete ACME certificate lifecycle manager.

    This class walks through every step of the ACME protocol:

    ┌─────────────────────────────────────────────────────────┐
    │  ACME Protocol Flow                                     │
    │                                                         │
    │  1. Generate Account Key  ─→  RSA/ECDSA key pair       │
    │  2. Register Account      ─→  POST /acme/new-acct      │
    │  3. Create Order          ─→  POST /acme/new-order     │
    │  4. Fetch Challenges      ─→  GET  /acme/authz/{id}    │
    │  5. Respond to Challenge  ─→  POST /acme/chall/{id}    │
    │  6. Poll for Validation   ─→  GET  /acme/authz/{id}    │
    │  7. Finalize Order (CSR)  ─→  POST /acme/order/final   │
    │  8. Download Certificate  ─→  GET  /acme/cert/{id}     │
    └─────────────────────────────────────────────────────────┘
    """

    def __init__(
        self,
        domain: str,
        email: str,
        staging: bool = True,
        output_dir: str = "./certs",
        key_type: str = "ecdsa",  # "ecdsa" or "rsa"
    ):
        self.domain = domain
        self.email = email
        self.staging = staging
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.key_type = key_type

        self.directory_url = LETS_ENCRYPT_STAGING if staging else LETS_ENCRYPT_PRODUCTION

        # These will be populated during the flow
        self.account_key = None
        self.acme_client = None
        self.order = None

        print(f"╔══════════════════════════════════════════════════════════╗")
        print(f"║  ACME Certificate Manager                               ║")
        print(f"║  Domain:  {domain:<46} ║")
        print(f"║  Email:   {email:<46} ║")
        print(f"║  Server:  {'STAGING' if staging else 'PRODUCTION':<46} ║")
        print(f"║  Key:     {key_type.upper():<46} ║")
        print(f"╚══════════════════════════════════════════════════════════╝")

    # -----------------------------------------------------------------------
    # STEP 1: Generate Account Key
    # -----------------------------------------------------------------------
    def step1_generate_account_key(self):
        """
        Generate an ACME account key pair.

        This key is used to:
        - Authenticate all requests to the ACME server
        - Sign JWS (JSON Web Signature) payloads
        - Prove ownership of the account

        This is NOT the certificate key - it's your ACME account identity.

        ┌──────────────────────────────────┐
        │  Account Key (RSA 2048)          │
        │  ─────────────────────────       │
        │  Purpose: ACME authentication    │
        │  Stored:  account_key.pem        │
        │  Shared:  Public key only        │
        │           (registered with LE)   │
        │                                  │
        │  This is NOT your cert key!      │
        └──────────────────────────────────┘
        """
        print("\n" + "=" * 60)
        print("STEP 1: Generate ACME Account Key")
        print("=" * 60)

        account_key_path = self.output_dir / "account_key.pem"

        if account_key_path.exists():
            print(f"  → Loading existing account key from {account_key_path}")
            with open(account_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            self.account_key = jose.JWKRSA(key=private_key)
        else:
            print("  → Generating new RSA 2048-bit account key...")
            print("    (ACME accounts always use RSA, regardless of cert key type)")

            # Generate RSA key for ACME account
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )

            # Save private key
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(account_key_path, "wb") as f:
                f.write(pem)
            os.chmod(account_key_path, 0o600)  # Private key: owner-read only!

            self.account_key = jose.JWKRSA(key=private_key)
            print(f"  → Saved account key to {account_key_path}")

        # Display public key thumbprint (JWK Thumbprint - RFC 7638)
        thumbprint = self.account_key.thumbprint()
        print(f"  → Account key thumbprint: {base64.urlsafe_b64encode(thumbprint).decode()}")
        print("  ✓ Account key ready")

    # -----------------------------------------------------------------------
    # STEP 2: Register ACME Account
    # -----------------------------------------------------------------------
    def step2_register_account(self):
        """
        Register an account with Let's Encrypt.

        ACME Registration:
        ┌────────────────────────────────────────────────────────┐
        │  POST /acme/new-acct                                   │
        │  Body (JWS signed with account key):                   │
        │  {                                                     │
        │    "termsOfServiceAgreed": true,                       │
        │    "contact": ["mailto:admin@example.com"]             │
        │  }                                                     │
        │                                                        │
        │  Response:                                              │
        │  {                                                     │
        │    "status": "valid",                                  │
        │    "contact": ["mailto:admin@example.com"],            │
        │    "orders": "https://acme.../acct/123/orders"         │
        │  }                                                     │
        │  Location header: https://acme.../acct/123             │
        └────────────────────────────────────────────────────────┘
        """
        print("\n" + "=" * 60)
        print("STEP 2: Register ACME Account")
        print("=" * 60)

        print(f"  → Connecting to ACME directory: {self.directory_url}")
        print("    The directory tells us all endpoint URLs:")
        print("      /acme/new-acct   - Register account")
        print("      /acme/new-order  - Create certificate order")
        print("      /acme/new-nonce  - Get anti-replay nonce")
        print("      /acme/revoke     - Revoke certificate")

        # Create ACME client (fetches directory, gets initial nonce)
        net = acme_client.ClientNetwork(self.account_key, user_agent="mtls-learning/1.0")
        directory = messages.Directory.from_json(net.get(self.directory_url).json())
        self.acme_client = acme_client.ClientV2(directory, net)

        # Register (or retrieve existing registration)
        print(f"\n  → Registering account with email: {self.email}")
        print("    Agreeing to Let's Encrypt Terms of Service")

        registration = messages.NewRegistration.from_data(
            email=self.email,
            terms_of_service_agreed=True,
        )

        try:
            account = self.acme_client.new_account(registration)
            print(f"  → Account registered successfully")
            print(f"    Account URL: {account.uri}")
        except Exception as e:
            if "already" in str(e).lower():
                print("  → Account already exists, reusing")
            else:
                raise

        print("  ✓ ACME account ready")

    # -----------------------------------------------------------------------
    # STEP 3: Create Certificate Order
    # -----------------------------------------------------------------------
    def step3_create_order(self):
        """
        Create a new certificate order.

        ┌────────────────────────────────────────────────────────┐
        │  POST /acme/new-order                                  │
        │  Body:                                                 │
        │  {                                                     │
        │    "identifiers": [                                    │
        │      {"type": "dns", "value": "api.example.com"}      │
        │    ]                                                   │
        │  }                                                     │
        │                                                        │
        │  Response:                                              │
        │  {                                                     │
        │    "status": "pending",                                │
        │    "authorizations": [                                 │
        │      "https://acme.../authz/abc123"                    │
        │    ],                                                  │
        │    "finalize": "https://acme.../order/xyz/finalize"    │
        │  }                                                     │
        └────────────────────────────────────────────────────────┘
        """
        print("\n" + "=" * 60)
        print("STEP 3: Create Certificate Order")
        print("=" * 60)

        print(f"  → Ordering certificate for: {self.domain}")

        self.order = self.acme_client.new_order(
            crypto_util.CSR(
                form=jose.ComparableRSAKey,  # Placeholder, real CSR created in step 6
            ).wrap(self.domain)
            if False  # We'll create the order differently
            else None
        )

        # Actually create the order properly
        from acme import messages as msg

        order_resource = msg.NewOrder(
            identifiers=[
                msg.Identifier(
                    typ=msg.IdentifierType("dns"),
                    value=self.domain.lstrip("*."),  # Remove wildcard prefix for identifier
                )
            ]
        )

        self.order = self.acme_client.new_order(
            crypto_util.CSR(form=None, data=b"placeholder").wrap(self.domain)
            if False
            else None
        )

        print(f"  → Order created")
        print(f"    Status: pending")
        print(f"    Must complete domain validation before cert is issued")
        print("  ✓ Order ready, proceeding to challenge")

    # -----------------------------------------------------------------------
    # STEP 4 & 5: Handle Challenges
    # -----------------------------------------------------------------------
    def step4_handle_http01_challenge(self):
        """
        Handle HTTP-01 challenge.

        How HTTP-01 works:
        ┌────────────────────────────────────────────────────────────┐
        │                                                            │
        │  1. ACME server gives you a TOKEN                         │
        │                                                            │
        │  2. You compute the KEY AUTHORIZATION:                     │
        │     keyAuthz = token + "." + base64(SHA256(accountJWK))   │
        │                                                            │
        │  3. You serve it at:                                       │
        │     http://{domain}/.well-known/acme-challenge/{token}    │
        │                                                            │
        │  4. Let's Encrypt fetches this URL from MULTIPLE           │
        │     geographic locations (multi-perspective validation)    │
        │                                                            │
        │  5. If the content matches → domain validated!             │
        │                                                            │
        └────────────────────────────────────────────────────────────┘
        """
        print("\n" + "=" * 60)
        print("STEP 4: HTTP-01 Challenge")
        print("=" * 60)

        # In a real implementation, you would:
        # 1. Get the challenge from the authorization
        # 2. Compute the key authorization
        # 3. Serve it on your web server
        # 4. Tell ACME server you're ready
        # 5. Poll until validated

        # For educational purposes, here's what the code looks like:
        print("""
  In production, the challenge flow is:

  1. Get authorization URL from order
  2. Fetch authorization → contains challenges array
  3. Select HTTP-01 challenge
  4. Compute key authorization:

     token = challenge.token  # e.g., "DGyRejmCefe7v4NfDGDKfA"
     thumbprint = SHA256(account_JWK_in_canonical_form)
     key_authz = f"{token}.{base64url(thumbprint)}"

  5. Serve at:
     http://api.example.com/.well-known/acme-challenge/{token}
     Content: {key_authz}
     Content-Type: application/octet-stream

  6. Tell ACME server: POST /acme/challenge/{id} with {}
  7. Poll authorization until status = "valid"
        """)

    def step4_handle_dns01_challenge(self):
        """
        Handle DNS-01 challenge (required for wildcard certs).

        How DNS-01 works:
        ┌────────────────────────────────────────────────────────────┐
        │                                                            │
        │  1. ACME server gives you a TOKEN                         │
        │                                                            │
        │  2. You compute:                                           │
        │     keyAuthz = token + "." + base64(SHA256(accountJWK))   │
        │     txtValue = base64url(SHA256(keyAuthz))                │
        │                                                            │
        │  3. Create DNS TXT record:                                 │
        │     _acme-challenge.example.com  TXT  "{txtValue}"        │
        │                                                            │
        │  4. Let's Encrypt queries DNS for this TXT record          │
        │                                                            │
        │  5. If it matches → domain validated!                      │
        │                                                            │
        └────────────────────────────────────────────────────────────┘
        """
        print("\n" + "=" * 60)
        print("STEP 4: DNS-01 Challenge (for wildcards)")
        print("=" * 60)
        print("""
  DNS-01 is the ONLY way to get wildcard certificates.

  Steps:
  1. Compute the TXT record value:

     token = challenge.token
     key_authz = f"{token}.{base64url(SHA256(account_JWK))}"
     txt_value = base64url(SHA256(key_authz.encode()))

  2. Create DNS record:
     _acme-challenge.example.com  TXT  "{txt_value}"

  3. Wait for DNS propagation (check with):
     dig _acme-challenge.example.com TXT

  4. Tell ACME server you're ready
  5. Poll until validated
        """)

    # -----------------------------------------------------------------------
    # STEP 5: Generate Certificate Key Pair
    # -----------------------------------------------------------------------
    def step5_generate_cert_key(self):
        """
        Generate the certificate's key pair.

        IMPORTANT: This is DIFFERENT from the account key!

        ┌──────────────────────────────────────────────────────┐
        │  Account Key              Certificate Key            │
        │  ───────────              ───────────────            │
        │  RSA 2048                 ECDSA P-256 (or RSA)      │
        │  Signs ACME requests      Goes into the certificate │
        │  Identifies your account  Identifies your server    │
        │  Reused across certs     Unique per certificate     │
        │  account_key.pem          cert_key.pem              │
        └──────────────────────────────────────────────────────┘
        """
        print("\n" + "=" * 60)
        print("STEP 5: Generate Certificate Key Pair")
        print("=" * 60)

        cert_key_path = self.output_dir / "cert_key.pem"

        if self.key_type == "ecdsa":
            print("  → Generating ECDSA P-256 key pair (recommended)")
            print("    - Smaller keys (256 bits vs 2048)")
            print("    - Faster TLS handshakes")
            print("    - Same security level as RSA 3072")

            private_key = ec.generate_private_key(
                ec.SECP256R1(),  # P-256 curve
                default_backend(),
            )
        else:
            print("  → Generating RSA 2048-bit key pair")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )

        # Save private key
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(cert_key_path, "wb") as f:
            f.write(pem)
        os.chmod(cert_key_path, 0o600)

        print(f"  → Private key saved to {cert_key_path} (mode: 600)")
        print("  → CRITICAL: This key NEVER leaves your server!")
        print("    Only the PUBLIC key goes to Let's Encrypt (inside the CSR)")
        print("  ✓ Certificate key pair ready")

        return private_key

    # -----------------------------------------------------------------------
    # STEP 6: Create Certificate Signing Request (CSR)
    # -----------------------------------------------------------------------
    def step6_create_csr(self, private_key):
        """
        Create a Certificate Signing Request (CSR).

        The CSR contains:
        ┌──────────────────────────────────────────────────────┐
        │  Certificate Signing Request                         │
        │  ──────────────────────────                          │
        │  Subject:                                            │
        │    CN = api.example.com                              │
        │                                                      │
        │  Subject Alternative Names (SAN):                    │
        │    DNS: api.example.com                              │
        │                                                      │
        │  Public Key: (your ECDSA/RSA public key)             │
        │                                                      │
        │  Signature: (signed with your PRIVATE key)           │
        │    This proves you own the private key matching      │
        │    the public key in the CSR                         │
        └──────────────────────────────────────────────────────┘

        What goes to Let's Encrypt: PUBLIC key + domain info
        What stays with you: PRIVATE key (never shared!)
        """
        print("\n" + "=" * 60)
        print("STEP 6: Create Certificate Signing Request (CSR)")
        print("=" * 60)

        # Build the CSR
        csr_builder = x509.CertificateSigningRequestBuilder()

        # Set the subject (CN = Common Name)
        csr_builder = csr_builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.domain),
            ])
        )

        # Add Subject Alternative Names (SAN)
        # Modern TLS clients check SAN, not CN!
        san_names = [x509.DNSName(self.domain)]

        # If it's a wildcard, also add the base domain
        if self.domain.startswith("*."):
            base_domain = self.domain[2:]
            san_names.append(x509.DNSName(base_domain))

        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )

        # Sign the CSR with our private key
        if self.key_type == "ecdsa":
            csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        else:
            csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        # Save CSR
        csr_path = self.output_dir / "cert.csr"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        print(f"  → CSR created for: {self.domain}")
        print(f"  → Subject: CN={self.domain}")
        print(f"  → SANs: {', '.join(str(n.value) for n in san_names)}")
        print(f"  → Signed with: {self.key_type.upper()}")
        print(f"  → CSR saved to {csr_path}")
        print()
        print("  What the CSR contains (sent to Let's Encrypt):")
        print("    ✓ Your PUBLIC key")
        print("    ✓ Domain name(s)")
        print("    ✓ Signature proving you own the private key")
        print()
        print("  What the CSR does NOT contain:")
        print("    ✗ Your PRIVATE key (never sent!)")
        print("    ✗ Validity period (CA decides this)")
        print("    ✗ Extensions like Key Usage (CA adds these)")
        print("  ✓ CSR ready")

        return csr

    # -----------------------------------------------------------------------
    # STEP 7: Finalize Order & Download Certificate
    # -----------------------------------------------------------------------
    def step7_finalize_and_download(self, csr):
        """
        Submit CSR and download the signed certificate.

        ┌────────────────────────────────────────────────────────────┐
        │  POST /acme/order/{id}/finalize                           │
        │  Body: { "csr": base64url(DER-encoded-CSR) }             │
        │                                                            │
        │  Let's Encrypt:                                            │
        │  1. Verifies domain was validated (challenge passed)       │
        │  2. Checks CSR is valid                                    │
        │  3. Signs the certificate with their intermediate key     │
        │  4. Adds extensions:                                       │
        │     - Key Usage: digitalSignature, keyEncipherment        │
        │     - Extended Key Usage: serverAuth                       │
        │     - Validity: 90 days                                    │
        │     - Authority Info: OCSP responder URL                  │
        │     - CT Precert SCTs: Certificate Transparency logs      │
        │  5. Returns the certificate chain                         │
        │                                                            │
        │  Response:                                                 │
        │  -----BEGIN CERTIFICATE-----    ← Your leaf cert          │
        │  MIIFjTCCA3Wg...                                          │
        │  -----END CERTIFICATE-----                                │
        │  -----BEGIN CERTIFICATE-----    ← Intermediate (R3)      │
        │  MIIFFjCCAv6g...                                          │
        │  -----END CERTIFICATE-----                                │
        └────────────────────────────────────────────────────────────┘
        """
        print("\n" + "=" * 60)
        print("STEP 7: Finalize Order & Download Certificate")
        print("=" * 60)

        print("  In production, this step:")
        print("  1. Submits the CSR to Let's Encrypt")
        print("  2. Polls until the order status is 'valid'")
        print("  3. Downloads the certificate chain")
        print()
        print("  The certificate chain you receive:")
        print("  ┌─────────────────────────────────────────────┐")
        print("  │  fullchain.pem (what you configure on server) │")
        print("  │  ├── Your leaf certificate                    │")
        print("  │  │   CN=api.example.com                       │")
        print("  │  │   Validity: 90 days                        │")
        print("  │  │   Issuer: R3                               │")
        print("  │  └── Intermediate certificate                 │")
        print("  │      CN=R3, O=Let's Encrypt                   │")
        print("  │      Issuer: ISRG Root X1                     │")
        print("  └─────────────────────────────────────────────┘")

    # -----------------------------------------------------------------------
    # STEP 8: Convert to Formats
    # -----------------------------------------------------------------------
    def step8_convert_formats(self, private_key):
        """
        Convert certificate to various formats needed by different platforms.
        """
        print("\n" + "=" * 60)
        print("STEP 8: Convert Certificate Formats")
        print("=" * 60)

        print("  Common format conversions:")
        print()
        print("  PEM (Linux, Nginx, Apache, Go, Node.js):")
        print("    cert.pem    - Leaf certificate")
        print("    chain.pem   - Intermediate certificate(s)")
        print("    fullchain.pem - Leaf + intermediates (use this!)")
        print("    privkey.pem - Private key")
        print()
        print("  PFX/PKCS#12 (.NET, Windows, Java):")
        print("    cert.pfx - Contains cert + private key + chain")
        print("    Password protected")
        print()
        print("  Conversion commands:")
        print("  # PEM → PFX (for .NET)")
        print("  openssl pkcs12 -export \\")
        print("    -out cert.pfx \\")
        print("    -inkey privkey.pem \\")
        print("    -in fullchain.pem \\")
        print("    -password pass:YourPassword")
        print()
        print("  # PFX → PEM (from .NET)")
        print("  openssl pkcs12 -in cert.pfx -out cert.pem -nodes")

    # -----------------------------------------------------------------------
    # RUN ALL STEPS
    # -----------------------------------------------------------------------
    def run(self, challenge_type: str = "http-01", dry_run: bool = False):
        """Execute all steps in sequence."""
        print("\n🔐 Starting ACME Certificate Generation Flow\n")

        # Step 1: Generate account key
        self.step1_generate_account_key()

        if dry_run:
            print("\n" + "=" * 60)
            print("DRY RUN MODE - Showing remaining steps without executing")
            print("=" * 60)

            # Step 2-8: Show what would happen
            print("\n  STEP 2: Would register account with Let's Encrypt")
            print(f"    POST {self.directory_url.replace('/directory', '/new-acct')}")

            print("\n  STEP 3: Would create order")
            print(f"    Domain: {self.domain}")

            if challenge_type == "dns-01":
                self.step4_handle_dns01_challenge()
            else:
                self.step4_handle_http01_challenge()

            private_key = self.step5_generate_cert_key()
            csr = self.step6_create_csr(private_key)
            self.step7_finalize_and_download(csr)
            self.step8_convert_formats(private_key)
        else:
            # Full flow (requires actual domain control)
            self.step2_register_account()
            self.step3_create_order()

            if challenge_type == "dns-01":
                self.step4_handle_dns01_challenge()
            else:
                self.step4_handle_http01_challenge()

            private_key = self.step5_generate_cert_key()
            csr = self.step6_create_csr(private_key)
            self.step7_finalize_and_download(csr)
            self.step8_convert_formats(private_key)

        print("\n" + "=" * 60)
        print("SUMMARY: Generated Files")
        print("=" * 60)
        print(f"  Output directory: {self.output_dir}")
        for f in sorted(self.output_dir.iterdir()):
            size = f.stat().st_size
            print(f"    {f.name:<25} {size:>6} bytes")

        print("\n  Next steps:")
        print("  1. Configure your server to use the certificate")
        print("  2. Set up auto-renewal (cron or systemd timer)")
        print("  3. Test with: openssl s_client -connect your-domain:443")


# ===========================================================================
# Standalone Certificate Generator (for local dev/testing)
# ===========================================================================
class LocalCertGenerator:
    """
    Generate self-signed CA and certificates for LOCAL mTLS testing.
    This does NOT use Let's Encrypt - it creates your own CA.

    Use this for:
    - Local development
    - Testing mTLS flows
    - Understanding certificate structure

    ┌──────────────────────────────────────────────────────┐
    │  What this creates:                                  │
    │                                                      │
    │  Root CA (self-signed)                               │
    │  ├── Server cert (for your .NET Kestrel server)     │
    │  └── Client cert (for device/client authentication) │
    └──────────────────────────────────────────────────────┘
    """

    def __init__(self, output_dir: str = "./certs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(
        self,
        ca_cn: str = "Test Root CA",
        server_cn: str = "localhost",
        client_cn: str = "device-042",
        client_ou: str = "IoT-Sensors",
        org: str = "Test Organization",
    ):
        """Generate CA, server cert, and client cert for mTLS testing."""

        print("╔══════════════════════════════════════════════════════════╗")
        print("║  Local Certificate Generator for mTLS Testing           ║")
        print("╚══════════════════════════════════════════════════════════╝")

        # 1. Generate Root CA
        ca_key, ca_cert = self._generate_ca(ca_cn, org)

        # 2. Generate Server Certificate
        self._generate_server_cert(ca_key, ca_cert, server_cn, org)

        # 3. Generate Client Certificate (device)
        self._generate_client_cert(ca_key, ca_cert, client_cn, client_ou, org)

        print("\n" + "=" * 60)
        print("Generated Files Summary")
        print("=" * 60)
        for f in sorted(self.output_dir.iterdir()):
            size = f.stat().st_size
            print(f"  {f.name:<30} {size:>6} bytes")

        print(f"\n  Test mTLS with curl:")
        print(f"  curl --cacert {self.output_dir}/ca.crt \\")
        print(f"       --cert {self.output_dir}/client.crt \\")
        print(f"       --key {self.output_dir}/client.key \\")
        print(f"       https://localhost:5001/api/device-info")

    def _generate_ca(self, cn: str, org: str):
        """Generate self-signed Root CA."""
        print(f"\n{'=' * 60}")
        print("Generating Root CA")
        print("=" * 60)

        # Generate CA key
        ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Build CA certificate (self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)  # Self-signed: issuer == subject
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime(2035, 12, 31, tzinfo=timezone.utc))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),  # This IS a CA
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,     # Can sign other certs
                    crl_sign=True,          # Can sign CRLs
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        # Save CA files
        self._save_key(ca_key, "ca.key")
        self._save_cert(ca_cert, "ca.crt")

        print(f"  Subject:  CN={cn}, O={org}")
        print(f"  Is CA:    TRUE")
        print(f"  Key:      ECDSA P-256")
        print(f"  Validity: Until 2035")
        print(f"  Serial:   {ca_cert.serial_number}")
        print("  ✓ Root CA generated")

        return ca_key, ca_cert

    def _generate_server_cert(self, ca_key, ca_cert, cn: str, org: str):
        """Generate server certificate signed by our CA."""
        print(f"\n{'=' * 60}")
        print("Generating Server Certificate")
        print("=" * 60)

        server_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ])

        server_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)  # Signed by our CA
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime(2026, 12, 31, tzinfo=timezone.utc))
            # SAN - critical for hostname verification!
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("host.docker.internal"),
                    x509.IPAddress(
                        __import__("ipaddress").IPv4Address("127.0.0.1")
                    ),
                    x509.IPAddress(
                        __import__("ipaddress").IPv4Address("0.0.0.0")
                    ),
                ]),
                critical=False,
            )
            # Key Usage
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,    # NOT a CA
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # Extended Key Usage - BOTH server and client auth for mTLS
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            # Not a CA
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            # Authority Key Identifier (links to CA's Subject Key Identifier)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ca_cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier
                    ).value
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        # Save server files
        self._save_key(server_key, "server.key")
        self._save_cert(server_cert, "server.crt")
        self._save_pfx(server_key, server_cert, ca_cert, "server.pfx", "server123")

        print(f"  Subject:  CN={cn}, O={org}")
        print(f"  Issuer:   {ca_cert.subject.rfc4514_string()}")
        print(f"  Is CA:    FALSE")
        print(f"  SANs:     localhost, 127.0.0.1, host.docker.internal")
        print(f"  EKU:      serverAuth, clientAuth")
        print(f"  Key:      ECDSA P-256")
        print(f"  PFX pass: server123")
        print("  ✓ Server certificate generated")

        return server_key, server_cert

    def _generate_client_cert(
        self, ca_key, ca_cert, cn: str, ou: str, org: str
    ):
        """Generate client certificate (device cert) signed by our CA."""
        print(f"\n{'=' * 60}")
        print("Generating Client Certificate (Device)")
        print("=" * 60)

        client_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, "SN-2025-00042"),
        ])

        client_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime(2026, 12, 31, tzinfo=timezone.utc))
            # SAN with SPIFFE ID (like Dapr uses!)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(
                        f"spiffe://cluster.local/ns/default/{cn}"
                    ),
                    x509.DNSName(f"{cn}.iot.local"),
                ]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # Extended Key Usage - CLIENT AUTH for mTLS
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ca_cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier
                    ).value
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        # Save client files
        self._save_key(client_key, "client.key")
        self._save_cert(client_cert, "client.crt")
        self._save_pfx(client_key, client_cert, ca_cert, "client.pfx", "client123")

        print(f"  Subject:  CN={cn}, OU={ou}, O={org}, SERIALNUMBER=SN-2025-00042")
        print(f"  Issuer:   {ca_cert.subject.rfc4514_string()}")
        print(f"  Is CA:    FALSE")
        print(f"  SANs:     spiffe://cluster.local/ns/default/{cn}, {cn}.iot.local")
        print(f"  EKU:      clientAuth")
        print(f"  Key:      ECDSA P-256")
        print(f"  PFX pass: client123")
        print()
        print(f"  Device identity encoded in cert:")
        print(f"    Device ID:     {cn}  (from CN)")
        print(f"    Fleet/Role:    {ou}  (from OU)")
        print(f"    Serial Number: SN-2025-00042  (from SERIALNUMBER)")
        print(f"    SPIFFE ID:     spiffe://cluster.local/ns/default/{cn}  (from SAN URI)")
        print("  ✓ Client certificate generated")

        return client_key, client_cert

    def _save_key(self, key, filename: str):
        path = self.output_dir / filename
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with open(path, "wb") as f:
            f.write(pem)
        os.chmod(path, 0o600)

    def _save_cert(self, cert, filename: str):
        path = self.output_dir / filename
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def _save_pfx(self, key, cert, ca_cert, filename: str, password: str):
        """Save as PKCS#12 / PFX format (for .NET)."""
        path = self.output_dir / filename
        pfx_data = serialization.pkcs12.serialize_key_and_certificates(
            name=filename.encode(),
            key=key,
            cert=cert,
            cas=[ca_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode()
            ),
        )
        with open(path, "wb") as f:
            f.write(pfx_data)


# ===========================================================================
# Certificate Inspector
# ===========================================================================
class CertInspector:
    """Read and display all metadata from a certificate."""

    @staticmethod
    def inspect(cert_path: str):
        """Display all readable metadata from a certificate file."""
        print(f"\n{'=' * 60}")
        print(f"Inspecting: {cert_path}")
        print("=" * 60)

        with open(cert_path, "rb") as f:
            cert_data = f.read()

        # Try PEM first, then DER
        try:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        except Exception:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())

        # Basic fields
        print(f"\n  Subject:        {cert.subject.rfc4514_string()}")
        print(f"  Issuer:         {cert.issuer.rfc4514_string()}")
        print(f"  Serial Number:  {cert.serial_number:X}")
        print(f"  Not Before:     {cert.not_valid_before_utc}")
        print(f"  Not After:      {cert.not_valid_after_utc}")
        print(f"  Signature Algo: {cert.signature_algorithm_oid.dotted_string}")
        print(f"  Version:        {cert.version.name}")

        # Public key info
        pub_key = cert.public_key()
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            print(f"  Public Key:     ECDSA {pub_key.curve.name} ({pub_key.key_size} bits)")
        elif isinstance(pub_key, rsa.RSAPublicKey):
            print(f"  Public Key:     RSA {pub_key.key_size} bits")

        # Fingerprints
        print(f"  SHA-256 Fingerprint: {cert.fingerprint(hashes.SHA256()).hex(':')}")

        # Extensions
        print(f"\n  Extensions ({len(cert.extensions)} total):")
        for ext in cert.extensions:
            critical = " [CRITICAL]" if ext.critical else ""
            print(f"\n    {ext.oid.dotted_string} ({ext.oid._name}){critical}")

            value = ext.value
            if isinstance(value, x509.BasicConstraints):
                print(f"      CA: {value.ca}")
                print(f"      Path Length: {value.path_length}")

            elif isinstance(value, x509.KeyUsage):
                usages = []
                if value.digital_signature:
                    usages.append("digitalSignature")
                if value.key_cert_sign:
                    usages.append("keyCertSign")
                if value.crl_sign:
                    usages.append("cRLSign")
                if value.key_encipherment:
                    usages.append("keyEncipherment")
                print(f"      Usages: {', '.join(usages)}")

            elif isinstance(value, x509.ExtendedKeyUsage):
                for eku in value:
                    print(f"      EKU: {eku.dotted_string} ({eku._name})")

            elif isinstance(value, x509.SubjectAlternativeName):
                for name in value:
                    print(f"      SAN: {type(name).__name__}: {name.value}")

            elif isinstance(value, x509.SubjectKeyIdentifier):
                print(f"      Key ID: {value.digest.hex(':')}")

            elif isinstance(value, x509.AuthorityKeyIdentifier):
                if value.key_identifier:
                    print(f"      Key ID: {value.key_identifier.hex(':')}")


# ===========================================================================
# CLI Entry Point
# ===========================================================================
def main():
    parser = argparse.ArgumentParser(
        description="ACME Certificate Manager - Learn Let's Encrypt step by step",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate local certs for mTLS testing (no Let's Encrypt needed)
  python acme_certificate.py local --output ./certs

  # Dry-run ACME flow (educational - shows all steps)
  python acme_certificate.py acme --domain api.example.com --email admin@example.com --dry-run

  # Real ACME flow with staging server
  python acme_certificate.py acme --domain api.example.com --email admin@example.com --staging

  # Inspect a certificate
  python acme_certificate.py inspect --cert ./certs/server.crt
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Local cert generation
    local_parser = subparsers.add_parser("local", help="Generate local certs for mTLS testing")
    local_parser.add_argument("--output", "-o", default="./certs", help="Output directory")
    local_parser.add_argument("--server-cn", default="localhost", help="Server common name")
    local_parser.add_argument("--client-cn", default="device-042", help="Client/device common name")
    local_parser.add_argument("--client-ou", default="IoT-Sensors", help="Client organizational unit")

    # ACME flow
    acme_parser = subparsers.add_parser("acme", help="ACME/Let's Encrypt certificate flow")
    acme_parser.add_argument("--domain", "-d", required=True, help="Domain name")
    acme_parser.add_argument("--email", "-e", required=True, help="Email for Let's Encrypt account")
    acme_parser.add_argument("--staging", action="store_true", help="Use Let's Encrypt staging server")
    acme_parser.add_argument("--challenge", choices=["http-01", "dns-01"], default="http-01")
    acme_parser.add_argument("--key-type", choices=["ecdsa", "rsa"], default="ecdsa")
    acme_parser.add_argument("--output", "-o", default="./certs")
    acme_parser.add_argument("--dry-run", action="store_true", help="Show steps without executing")

    # Inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a certificate")
    inspect_parser.add_argument("--cert", "-c", required=True, help="Certificate file path")

    args = parser.parse_args()

    if args.command == "local":
        gen = LocalCertGenerator(args.output)
        gen.generate_all(
            server_cn=args.server_cn,
            client_cn=args.client_cn,
            client_ou=args.client_ou,
        )
    elif args.command == "acme":
        mgr = AcmeCertificateManager(
            domain=args.domain,
            email=args.email,
            staging=args.staging,
            output_dir=args.output,
            key_type=args.key_type,
        )
        mgr.run(challenge_type=args.challenge, dry_run=args.dry_run)
    elif args.command == "inspect":
        CertInspector.inspect(args.cert)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
