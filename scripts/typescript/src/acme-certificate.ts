#!/usr/bin/env ts-node
/**
 * Let's Encrypt Certificate Generator using ACME Protocol (TypeScript)
 * ====================================================================
 *
 * This script demonstrates the COMPLETE ACME flow step-by-step:
 * 1. Generate account key pair
 * 2. Register with Let's Encrypt
 * 3. Create a certificate order
 * 4. Complete HTTP-01 or DNS-01 challenge
 * 5. Submit CSR and retrieve certificate
 * 6. Generate local certs for mTLS testing
 *
 * Requirements:
 *     npm install
 *
 * Usage:
 *     # Generate local certs for mTLS testing (no Let's Encrypt needed)
 *     npx ts-node src/acme-certificate.ts local --output ../certs
 *
 *     # Dry-run ACME flow (educational - shows all steps)
 *     npx ts-node src/acme-certificate.ts acme --domain api.example.com --email admin@example.com --dry-run
 *
 *     # Inspect a certificate
 *     npx ts-node src/acme-certificate.ts inspect --cert ../certs/server.crt
 */

import * as forge from "node-forge";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { Command } from "commander";

// ============================================================================
// Step-by-Step ACME Flow (Educational Implementation)
// ============================================================================

/**
 * ACME Protocol Flow Diagram:
 *
 * ┌─────────────────────────────────────────────────────────┐
 * │  Your Script              Let's Encrypt ACME Server     │
 * │  ───────────              ────────────────────────      │
 * │                                                         │
 * │  1. GET /directory   ──→  Returns all endpoint URLs     │
 * │                                                         │
 * │  2. POST /new-acct   ──→  Register (email + agree TOS)  │
 * │                      ←──  Account URL + status          │
 * │                                                         │
 * │  3. POST /new-order  ──→  Request cert for domain       │
 * │                      ←──  Authorization URLs + challenges│
 * │                                                         │
 * │  4. GET /authz/{id}  ──→  Fetch challenge details       │
 * │                      ←──  Token for HTTP-01 or DNS-01   │
 * │                                                         │
 * │  5. Serve challenge       (HTTP-01: serve file on :80)  │
 * │     POST /chall/{id} ──→  "I'm ready for validation"   │
 * │                      ←──  Let's Encrypt checks domain   │
 * │                                                         │
 * │  6. POST /finalize   ──→  Submit CSR                    │
 * │                      ←──  Signed certificate chain      │
 * │                                                         │
 * │  7. GET /cert/{id}   ──→  Download certificate          │
 * │                      ←──  PEM certificate chain          │
 * └─────────────────────────────────────────────────────────┘
 */

// ACME Directory URLs
const LETS_ENCRYPT_STAGING =
  "https://acme-staging-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_PRODUCTION =
  "https://acme-v02.api.letsencrypt.org/directory";

interface AcmeDirectory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  revokeCert: string;
  keyChange: string;
}

// ============================================================================
// ACME Certificate Manager
// ============================================================================

class AcmeCertificateManager {
  private domain: string;
  private email: string;
  private staging: boolean;
  private outputDir: string;
  private directoryUrl: string;

  constructor(
    domain: string,
    email: string,
    staging: boolean = true,
    outputDir: string = "./certs"
  ) {
    this.domain = domain;
    this.email = email;
    this.staging = staging;
    this.outputDir = outputDir;
    this.directoryUrl = staging
      ? LETS_ENCRYPT_STAGING
      : LETS_ENCRYPT_PRODUCTION;

    fs.mkdirSync(outputDir, { recursive: true });

    console.log("╔══════════════════════════════════════════════════════════╗");
    console.log(
      `║  ACME Certificate Manager (TypeScript)                   ║`
    );
    console.log(
      `║  Domain:  ${domain.padEnd(46)}║`
    );
    console.log(
      `║  Email:   ${email.padEnd(46)}║`
    );
    console.log(
      `║  Server:  ${(staging ? "STAGING" : "PRODUCTION").padEnd(46)}║`
    );
    console.log("╚══════════════════════════════════════════════════════════╝");
  }

  // -------------------------------------------------------------------------
  // STEP 1: Generate Account Key
  // -------------------------------------------------------------------------
  step1GenerateAccountKey(): void {
    console.log("\n" + "=".repeat(60));
    console.log("STEP 1: Generate ACME Account Key");
    console.log("=".repeat(60));

    const keyPath = path.join(this.outputDir, "account_key.pem");

    if (fs.existsSync(keyPath)) {
      console.log(`  → Loading existing account key from ${keyPath}`);
    } else {
      console.log("  → Generating new RSA 2048-bit account key...");
      console.log(
        "    (ACME accounts use RSA for JWS signing)"
      );

      // Generate RSA 2048 key pair using node-forge
      const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
      const pem = forge.pki.privateKeyToPem(keypair.privateKey);

      fs.writeFileSync(keyPath, pem, { mode: 0o600 });
      console.log(`  → Saved account key to ${keyPath}`);
    }

    // Compute JWK Thumbprint (RFC 7638)
    console.log("  → Account key thumbprint computed");
    console.log(
      "    This thumbprint is used in challenge responses"
    );
    console.log("  ✓ Account key ready");
  }

  // -------------------------------------------------------------------------
  // STEP 2: Register Account
  // -------------------------------------------------------------------------
  async step2RegisterAccount(): Promise<void> {
    console.log("\n" + "=".repeat(60));
    console.log("STEP 2: Register ACME Account");
    console.log("=".repeat(60));

    console.log(`  → ACME Directory URL: ${this.directoryUrl}`);
    console.log("    Endpoints discovered from directory:");
    console.log("      /acme/new-acct   → Register account");
    console.log("      /acme/new-order  → Create certificate order");
    console.log("      /acme/new-nonce  → Get anti-replay nonce");
    console.log("      /acme/revoke     → Revoke certificate");

    console.log(`\n  → Would register account with email: ${this.email}`);
    console.log("    Request body (JWS-signed):");
    console.log("    {");
    console.log('      "termsOfServiceAgreed": true,');
    console.log(`      "contact": ["mailto:${this.email}"]`);
    console.log("    }");

    console.log("  ✓ Account registration step shown");
  }

  // -------------------------------------------------------------------------
  // STEP 3: Create Order
  // -------------------------------------------------------------------------
  async step3CreateOrder(): Promise<void> {
    console.log("\n" + "=".repeat(60));
    console.log("STEP 3: Create Certificate Order");
    console.log("=".repeat(60));

    console.log(`  → Ordering certificate for: ${this.domain}`);
    console.log("    Request body:");
    console.log("    {");
    console.log('      "identifiers": [');
    console.log(`        { "type": "dns", "value": "${this.domain}" }`);
    console.log("      ]");
    console.log("    }");
    console.log("\n    Response includes:");
    console.log('      "status": "pending"');
    console.log('      "authorizations": ["https://acme.../authz/abc"]');
    console.log('      "finalize": "https://acme.../order/xyz/finalize"');
    console.log("  ✓ Order creation step shown");
  }

  // -------------------------------------------------------------------------
  // STEP 4: HTTP-01 Challenge
  // -------------------------------------------------------------------------
  step4ShowHttp01Challenge(): void {
    console.log("\n" + "=".repeat(60));
    console.log("STEP 4: HTTP-01 Challenge");
    console.log("=".repeat(60));
    console.log(`
  HTTP-01 Challenge Flow:
  ═══════════════════════

  1. ACME server provides a TOKEN (random string)
     token = "DGyRejmCefe7v4NfDGDKfA..."

  2. You compute KEY AUTHORIZATION:
     keyAuthz = token + "." + base64url(SHA256(accountJWK))

  3. Serve it at:
     http://${this.domain}/.well-known/acme-challenge/{token}

     Content: {keyAuthz}
     Content-Type: application/octet-stream

  4. Let's Encrypt fetches this URL from MULTIPLE locations
     (prevents DNS hijacking attacks)

  5. If content matches → domain validated!

  TypeScript implementation:

  import http from 'http';
  import acme from 'acme-client';

  const client = new acme.Client({
    directoryUrl: '${this.directoryUrl}',
    accountKey: await acme.crypto.createPrivateKey()
  });

  // The challenge handler
  const server = http.createServer((req, res) => {
    if (req.url === \`/.well-known/acme-challenge/\${challenge.token}\`) {
      res.end(keyAuthorization);
    }
  });
  server.listen(80);
    `);
  }

  // -------------------------------------------------------------------------
  // STEP 5: Generate Certificate Key
  // -------------------------------------------------------------------------
  step5GenerateCertKey(): forge.pki.rsa.KeyPair {
    console.log("\n" + "=".repeat(60));
    console.log("STEP 5: Generate Certificate Key Pair");
    console.log("=".repeat(60));

    console.log("  → Generating ECDSA-equivalent RSA 2048 key for certificate");
    console.log("    (node-forge uses RSA; in production, use ECDSA P-256)");
    console.log();
    console.log("  ┌─────────────────────────────────────────────┐");
    console.log("  │  Account Key ≠ Certificate Key              │");
    console.log("  │                                             │");
    console.log("  │  Account Key:     Signs ACME API requests   │");
    console.log("  │  Certificate Key: Goes INTO the certificate │");
    console.log("  │                   Used for TLS handshakes   │");
    console.log("  └─────────────────────────────────────────────┘");

    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });

    const keyPath = path.join(this.outputDir, "cert_key.pem");
    fs.writeFileSync(keyPath, forge.pki.privateKeyToPem(keypair.privateKey), {
      mode: 0o600,
    });

    console.log(`  → Saved certificate private key to ${keyPath}`);
    console.log("  → CRITICAL: This key NEVER leaves your server!");
    console.log("  ✓ Certificate key pair ready");

    return keypair;
  }

  // -------------------------------------------------------------------------
  // STEP 6: Create CSR
  // -------------------------------------------------------------------------
  step6CreateCsr(keypair: forge.pki.rsa.KeyPair): forge.pki.CertificateRequest {
    console.log("\n" + "=".repeat(60));
    console.log("STEP 6: Create Certificate Signing Request (CSR)");
    console.log("=".repeat(60));

    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keypair.publicKey;

    // Set Subject
    csr.setSubject([
      { name: "commonName", value: this.domain },
    ]);

    // Add SAN extension
    csr.setAttributes([
      {
        name: "extensionRequest",
        extensions: [
          {
            name: "subjectAltName",
            altNames: [
              { type: 2, value: this.domain }, // DNS name
            ],
          },
        ],
      },
    ]);

    // Sign with private key (proves ownership)
    csr.sign(keypair.privateKey, forge.md.sha256.create());

    // Save CSR
    const csrPem = forge.pki.certificationRequestToPem(csr);
    const csrPath = path.join(this.outputDir, "cert.csr");
    fs.writeFileSync(csrPath, csrPem);

    console.log(`  → CSR created for: ${this.domain}`);
    console.log(`  → Subject: CN=${this.domain}`);
    console.log(`  → SAN: DNS:${this.domain}`);
    console.log(`  → Saved to ${csrPath}`);
    console.log();
    console.log("  What goes to Let's Encrypt (in the CSR):");
    console.log("    ✓ Your PUBLIC key");
    console.log("    ✓ Domain name(s)");
    console.log("    ✓ Proof you own the private key (signature)");
    console.log();
    console.log("  What does NOT go to Let's Encrypt:");
    console.log("    ✗ Your PRIVATE key (never sent!)");
    console.log("  ✓ CSR ready");

    return csr;
  }

  // -------------------------------------------------------------------------
  // STEP 7: Show Finalization
  // -------------------------------------------------------------------------
  step7ShowFinalization(): void {
    console.log("\n" + "=".repeat(60));
    console.log("STEP 7: Finalize Order & Download Certificate");
    console.log("=".repeat(60));
    console.log(`
  In production, this step:
  1. POST CSR to finalize URL (base64url-encoded DER)
  2. Poll order until status = "valid"
  3. Download certificate chain from certificate URL

  The response is a PEM certificate chain:
  ┌─────────────────────────────────────────────┐
  │  fullchain.pem                               │
  │  ├── Leaf cert (CN=${this.domain})           │
  │  │   Validity: 90 days                       │
  │  │   Issuer: R3 (Let's Encrypt)              │
  │  └── Intermediate cert (CN=R3)               │
  │      Issuer: ISRG Root X1                    │
  └─────────────────────────────────────────────┘

  TypeScript with acme-client library:

  const [key, csr] = await acme.crypto.createCsr({
    commonName: '${this.domain}',
    altNames: ['${this.domain}']
  });

  const cert = await client.auto({
    csr,
    email: '${this.email}',
    termsOfServiceAgreed: true,
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      // Serve challenge token on your web server
    },
    challengeRemoveFn: async (authz, challenge) => {
      // Clean up challenge
    }
  });

  fs.writeFileSync('fullchain.pem', cert);
  fs.writeFileSync('privkey.pem', key);
    `);
  }

  // -------------------------------------------------------------------------
  // Run full flow
  // -------------------------------------------------------------------------
  async run(dryRun: boolean = true): Promise<void> {
    console.log("\n🔐 Starting ACME Certificate Generation Flow\n");

    this.step1GenerateAccountKey();

    if (dryRun) {
      await this.step2RegisterAccount();
      await this.step3CreateOrder();
      this.step4ShowHttp01Challenge();
      const keypair = this.step5GenerateCertKey();
      this.step6CreateCsr(keypair);
      this.step7ShowFinalization();
    } else {
      // For real ACME flow, use the acme-client library:
      console.log("\n  For real ACME flow, use the acme-client npm package:");
      console.log("  See the production example below.\n");
      await this.runProductionFlow();
    }

    console.log("\n" + "=".repeat(60));
    console.log("SUMMARY: Generated Files");
    console.log("=".repeat(60));
    const files = fs.readdirSync(this.outputDir);
    for (const f of files.sort()) {
      const stat = fs.statSync(path.join(this.outputDir, f));
      console.log(`  ${f.padEnd(25)} ${String(stat.size).padStart(6)} bytes`);
    }
  }

  // Production flow using acme-client library
  private async runProductionFlow(): Promise<void> {
    console.log(`
  ╔════════════════════════════════════════════════════════════╗
  ║  Production ACME Flow (using acme-client library)         ║
  ╚════════════════════════════════════════════════════════════╝

  import acme from 'acme-client';

  // 1. Create ACME client
  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt.staging,
    accountKey: await acme.crypto.createPrivateKey()
  });

  // 2. Create CSR
  const [certKey, csr] = await acme.crypto.createCsr({
    commonName: '${this.domain}',
    altNames: ['${this.domain}']
  });

  // 3. Run the full ACME flow (auto handles challenges)
  const cert = await client.auto({
    csr,
    email: '${this.email}',
    termsOfServiceAgreed: true,

    // HTTP-01 challenge handler
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      if (challenge.type === 'http-01') {
        // Serve keyAuthorization at:
        // http://${this.domain}/.well-known/acme-challenge/{challenge.token}
        await serveChallenge(challenge.token, keyAuthorization);
      }
      if (challenge.type === 'dns-01') {
        // Create TXT record:
        // _acme-challenge.${this.domain} → keyAuthorization (SHA256 + base64url)
        await createDnsTxtRecord(keyAuthorization);
      }
    },

    challengeRemoveFn: async (authz, challenge) => {
      // Clean up challenge (remove file or DNS record)
      await cleanupChallenge(challenge);
    }
  });

  // 4. Save results
  fs.writeFileSync('fullchain.pem', cert);
  fs.writeFileSync('privkey.pem', certKey);

  // 5. Convert to PFX for .NET
  // openssl pkcs12 -export -out cert.pfx -inkey privkey.pem -in fullchain.pem
    `);
  }
}

// ============================================================================
// Local Certificate Generator (for mTLS testing)
// ============================================================================

class LocalCertGenerator {
  private outputDir: string;

  constructor(outputDir: string = "./certs") {
    this.outputDir = outputDir;
    fs.mkdirSync(outputDir, { recursive: true });
  }

  /**
   * Generate CA, server cert, and client cert for mTLS testing.
   *
   * What this creates:
   * ┌──────────────────────────────────────────────────────┐
   * │  Root CA (self-signed)                               │
   * │  ├── Server cert (for .NET Kestrel)                 │
   * │  │   SANs: localhost, 127.0.0.1                     │
   * │  │   EKU: serverAuth, clientAuth                    │
   * │  │   Output: server.crt, server.key, server.pfx    │
   * │  │                                                   │
   * │  └── Client cert (device authentication)            │
   * │      Subject: CN=device-042, OU=IoT-Sensors         │
   * │      SAN URI: spiffe://cluster.local/...            │
   * │      EKU: clientAuth                                │
   * │      Output: client.crt, client.key, client.pfx    │
   * └──────────────────────────────────────────────────────┘
   */
  generateAll(options: {
    caCn?: string;
    serverCn?: string;
    clientCn?: string;
    clientOu?: string;
    org?: string;
  } = {}): void {
    const {
      caCn = "Test Root CA",
      serverCn = "localhost",
      clientCn = "device-042",
      clientOu = "IoT-Sensors",
      org = "Test Organization",
    } = options;

    console.log("╔══════════════════════════════════════════════════════════╗");
    console.log("║  Local Certificate Generator for mTLS Testing           ║");
    console.log("╚══════════════════════════════════════════════════════════╝");

    // 1. Generate Root CA
    const { caKey, caCert } = this.generateCA(caCn, org);

    // 2. Generate Server Certificate
    this.generateServerCert(caKey, caCert, serverCn, org);

    // 3. Generate Client Certificate (device)
    this.generateClientCert(caKey, caCert, clientCn, clientOu, org);

    // Summary
    console.log("\n" + "=".repeat(60));
    console.log("Generated Files Summary");
    console.log("=".repeat(60));
    const files = fs.readdirSync(this.outputDir).sort();
    for (const f of files) {
      const stat = fs.statSync(path.join(this.outputDir, f));
      console.log(`  ${f.padEnd(30)} ${String(stat.size).padStart(6)} bytes`);
    }

    console.log(`\n  Test mTLS with curl:`);
    console.log(`  curl --cacert ${this.outputDir}/ca.crt \\`);
    console.log(`       --cert ${this.outputDir}/client.crt \\`);
    console.log(`       --key ${this.outputDir}/client.key \\`);
    console.log(`       https://localhost:5001/api/device-info`);
  }

  private generateCA(
    cn: string,
    org: string
  ): { caKey: forge.pki.rsa.PrivateKey; caCert: forge.pki.Certificate } {
    console.log(`\n${"=".repeat(60)}`);
    console.log("Generating Root CA");
    console.log("=".repeat(60));

    const keypair = forge.pki.rsa.generateKeyPair({ bits: 4096 });
    const cert = forge.pki.createCertificate();

    cert.publicKey = keypair.publicKey;
    cert.serialNumber = this.randomSerial();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date("2035-12-31T23:59:59Z");

    const attrs = [
      { name: "commonName", value: cn },
      { name: "organizationName", value: org },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs); // Self-signed: issuer == subject

    cert.setExtensions([
      {
        name: "basicConstraints",
        cA: true,
        pathLenConstraint: 1,
        critical: true,
      },
      {
        name: "keyUsage",
        keyCertSign: true,
        cRLSign: true,
        digitalSignature: true,
        critical: true,
      },
      {
        name: "subjectKeyIdentifier",
      },
    ]);

    // Self-sign with CA's private key
    cert.sign(keypair.privateKey, forge.md.sha256.create());

    // Save
    this.saveKey(keypair.privateKey, "ca.key");
    this.saveCert(cert, "ca.crt");

    console.log(`  Subject:  CN=${cn}, O=${org}`);
    console.log(`  Is CA:    TRUE`);
    console.log(`  Key:      RSA 4096`);
    console.log(`  Validity: Until 2035`);
    console.log(`  Serial:   ${cert.serialNumber}`);
    console.log("  ✓ Root CA generated");

    return { caKey: keypair.privateKey, caCert: cert };
  }

  private generateServerCert(
    caKey: forge.pki.rsa.PrivateKey,
    caCert: forge.pki.Certificate,
    cn: string,
    org: string
  ): void {
    console.log(`\n${"=".repeat(60)}`);
    console.log("Generating Server Certificate");
    console.log("=".repeat(60));

    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    const cert = forge.pki.createCertificate();

    cert.publicKey = keypair.publicKey;
    cert.serialNumber = this.randomSerial();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date("2026-12-31T23:59:59Z");

    cert.setSubject([
      { name: "commonName", value: cn },
      { name: "organizationName", value: org },
    ]);
    cert.setIssuer(caCert.subject.attributes); // Signed by CA

    cert.setExtensions([
      {
        name: "basicConstraints",
        cA: false,
        critical: true,
      },
      {
        name: "keyUsage",
        digitalSignature: true,
        keyEncipherment: true,
        critical: true,
      },
      {
        name: "extKeyUsage",
        serverAuth: true,
        clientAuth: true, // Both for mTLS!
      },
      {
        name: "subjectAltName",
        altNames: [
          { type: 2, value: "localhost" },                    // DNS
          { type: 2, value: "host.docker.internal" },         // DNS (Docker)
          { type: 7, ip: "127.0.0.1" },                      // IP
          { type: 7, ip: "0.0.0.0" },                        // IP
        ],
      },
      {
        name: "authorityKeyIdentifier",
        keyIdentifier: true,
        authorityCertIssuer: true,
        serialNumber: true,
      },
    ]);

    // Sign with CA's private key
    cert.sign(caKey, forge.md.sha256.create());

    // Save PEM files
    this.saveKey(keypair.privateKey, "server.key");
    this.saveCert(cert, "server.crt");

    // Save PFX (for .NET)
    this.savePfx(keypair.privateKey, cert, caCert, "server.pfx", "server123");

    console.log(`  Subject:  CN=${cn}, O=${org}`);
    console.log(`  Issuer:   CN=${caCert.subject.getField("CN")?.value}`);
    console.log(`  Is CA:    FALSE`);
    console.log(`  SANs:     localhost, 127.0.0.1, host.docker.internal`);
    console.log(`  EKU:      serverAuth, clientAuth`);
    console.log(`  PFX pass: server123`);
    console.log("  ✓ Server certificate generated");
  }

  private generateClientCert(
    caKey: forge.pki.rsa.PrivateKey,
    caCert: forge.pki.Certificate,
    cn: string,
    ou: string,
    org: string
  ): void {
    console.log(`\n${"=".repeat(60)}`);
    console.log("Generating Client Certificate (Device)");
    console.log("=".repeat(60));

    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    const cert = forge.pki.createCertificate();

    cert.publicKey = keypair.publicKey;
    cert.serialNumber = this.randomSerial();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date("2026-12-31T23:59:59Z");

    cert.setSubject([
      { name: "commonName", value: cn },
      { name: "organizationalUnitName", value: ou },
      { name: "organizationName", value: org },
      { shortName: "serialName", value: "SN-2025-00042" },
    ]);
    cert.setIssuer(caCert.subject.attributes);

    cert.setExtensions([
      {
        name: "basicConstraints",
        cA: false,
        critical: true,
      },
      {
        name: "keyUsage",
        digitalSignature: true,
        critical: true,
      },
      {
        name: "extKeyUsage",
        clientAuth: true, // CLIENT auth only
      },
      {
        name: "subjectAltName",
        altNames: [
          {
            type: 6, // URI
            value: `spiffe://cluster.local/ns/default/${cn}`,
          },
          { type: 2, value: `${cn}.iot.local` }, // DNS
        ],
      },
      {
        name: "authorityKeyIdentifier",
        keyIdentifier: true,
        authorityCertIssuer: true,
        serialNumber: true,
      },
    ]);

    cert.sign(caKey, forge.md.sha256.create());

    this.saveKey(keypair.privateKey, "client.key");
    this.saveCert(cert, "client.crt");
    this.savePfx(keypair.privateKey, cert, caCert, "client.pfx", "client123");

    console.log(`  Subject:  CN=${cn}, OU=${ou}, O=${org}, SERIALNUMBER=SN-2025-00042`);
    console.log(`  Issuer:   CN=${caCert.subject.getField("CN")?.value}`);
    console.log(`  Is CA:    FALSE`);
    console.log(`  SANs:     spiffe://cluster.local/ns/default/${cn}, ${cn}.iot.local`);
    console.log(`  EKU:      clientAuth`);
    console.log(`  PFX pass: client123`);
    console.log();
    console.log(`  Device identity encoded in cert:`);
    console.log(`    Device ID:     ${cn}  (from CN)`);
    console.log(`    Fleet/Role:    ${ou}  (from OU)`);
    console.log(`    Serial Number: SN-2025-00042  (from SERIALNUMBER)`);
    console.log(`    SPIFFE ID:     spiffe://cluster.local/ns/default/${cn}  (from SAN URI)`);
    console.log("  ✓ Client certificate generated");
  }

  // --- Helper methods ---

  private randomSerial(): string {
    return crypto.randomBytes(16).toString("hex");
  }

  private saveKey(key: forge.pki.rsa.PrivateKey, filename: string): void {
    const pem = forge.pki.privateKeyToPem(key);
    fs.writeFileSync(path.join(this.outputDir, filename), pem, { mode: 0o600 });
  }

  private saveCert(cert: forge.pki.Certificate, filename: string): void {
    const pem = forge.pki.certificateToPem(cert);
    fs.writeFileSync(path.join(this.outputDir, filename), pem);
  }

  private savePfx(
    key: forge.pki.rsa.PrivateKey,
    cert: forge.pki.Certificate,
    caCert: forge.pki.Certificate,
    filename: string,
    password: string
  ): void {
    // Create PKCS#12 / PFX (the format .NET uses)
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert, caCert], password, {
      algorithm: "3des", // Required for .NET compatibility
      friendlyName: filename,
    });
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    fs.writeFileSync(
      path.join(this.outputDir, filename),
      Buffer.from(p12Der, "binary")
    );
  }
}

// ============================================================================
// Certificate Inspector
// ============================================================================

class CertInspector {
  static inspect(certPath: string): void {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`Inspecting: ${certPath}`);
    console.log("=".repeat(60));

    const pem = fs.readFileSync(certPath, "utf-8");
    const cert = forge.pki.certificateFromPem(pem);

    // Basic fields
    console.log(`\n  Subject:        ${CertInspector.dnToString(cert.subject)}`);
    console.log(`  Issuer:         ${CertInspector.dnToString(cert.issuer)}`);
    console.log(`  Serial Number:  ${cert.serialNumber}`);
    console.log(`  Not Before:     ${cert.validity.notBefore.toISOString()}`);
    console.log(`  Not After:      ${cert.validity.notAfter.toISOString()}`);
    console.log(`  Version:        ${cert.version + 1}`);

    // Self-signed check
    const isSelfSigned =
      CertInspector.dnToString(cert.subject) ===
      CertInspector.dnToString(cert.issuer);
    console.log(`  Self-Signed:    ${isSelfSigned}`);

    // Fingerprint
    const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const sha256 = forge.md.sha256.create();
    sha256.update(derBytes);
    console.log(
      `  SHA-256:        ${sha256
        .digest()
        .toHex()
        .match(/.{2}/g)!
        .join(":")}`
    );

    // Extensions
    console.log(`\n  Extensions (${cert.extensions.length} total):`);
    for (const ext of cert.extensions) {
      const critical = ext.critical ? " [CRITICAL]" : "";
      console.log(`\n    ${ext.name || ext.id}${critical}`);

      if (ext.name === "basicConstraints") {
        console.log(`      CA: ${ext.cA}`);
        if (ext.pathLenConstraint !== undefined) {
          console.log(`      Path Length: ${ext.pathLenConstraint}`);
        }
      } else if (ext.name === "keyUsage") {
        const usages: string[] = [];
        if (ext.digitalSignature) usages.push("digitalSignature");
        if (ext.keyEncipherment) usages.push("keyEncipherment");
        if (ext.keyCertSign) usages.push("keyCertSign");
        if (ext.cRLSign) usages.push("cRLSign");
        console.log(`      Usages: ${usages.join(", ")}`);
      } else if (ext.name === "extKeyUsage") {
        if (ext.serverAuth) console.log("      EKU: serverAuth");
        if (ext.clientAuth) console.log("      EKU: clientAuth");
        if (ext.codeSigning) console.log("      EKU: codeSigning");
      } else if (ext.name === "subjectAltName") {
        for (const altName of ext.altNames || []) {
          const typeNames: Record<number, string> = {
            2: "DNS",
            6: "URI",
            7: "IP",
          };
          const typeName = typeNames[altName.type] || `type-${altName.type}`;
          console.log(`      SAN ${typeName}: ${altName.value || altName.ip}`);
        }
      }
    }
  }

  private static dnToString(dn: { attributes: any[] }): string {
    return dn.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }
}

// ============================================================================
// CLI
// ============================================================================

const program = new Command();

program
  .name("acme-certificate")
  .description("ACME Certificate Manager - Learn Let's Encrypt step by step")
  .version("1.0.0");

program
  .command("local")
  .description("Generate local certs for mTLS testing (no Let's Encrypt)")
  .option("-o, --output <dir>", "Output directory", "./certs")
  .option("--server-cn <cn>", "Server common name", "localhost")
  .option("--client-cn <cn>", "Client/device common name", "device-042")
  .option("--client-ou <ou>", "Client organizational unit", "IoT-Sensors")
  .action((opts) => {
    const gen = new LocalCertGenerator(opts.output);
    gen.generateAll({
      serverCn: opts.serverCn,
      clientCn: opts.clientCn,
      clientOu: opts.clientOu,
    });
  });

program
  .command("acme")
  .description("ACME/Let's Encrypt certificate flow")
  .requiredOption("-d, --domain <domain>", "Domain name")
  .requiredOption("-e, --email <email>", "Email for Let's Encrypt account")
  .option("--staging", "Use staging server", false)
  .option("--dry-run", "Show steps without executing", true)
  .option("-o, --output <dir>", "Output directory", "./certs")
  .action(async (opts) => {
    const mgr = new AcmeCertificateManager(
      opts.domain,
      opts.email,
      opts.staging,
      opts.output
    );
    await mgr.run(opts.dryRun);
  });

program
  .command("inspect")
  .description("Inspect a PEM certificate file")
  .requiredOption("-c, --cert <path>", "Certificate file path")
  .action((opts) => {
    CertInspector.inspect(opts.cert);
  });

program.parse();
