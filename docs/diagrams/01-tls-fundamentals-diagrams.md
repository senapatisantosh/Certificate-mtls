# 01 - TLS Fundamentals & Let's Encrypt - Diagrams

## 1.1 Asymmetric Cryptography - How Key Pairs Work

```mermaid
flowchart TD
    A[Key Generation Algorithm<br/>RSA-2048 / ECDSA P-256] --> B[🔑 Private Key<br/>Keep SECRET]
    A --> C[🔓 Public Key<br/>Share freely]

    B --> D[Sign Data]
    B --> E[Decrypt Data]
    C --> F[Verify Signature]
    C --> G[Encrypt Data]

    D -.->|Anyone can verify<br/>with public key| F
    G -.->|Only private key<br/>can decrypt| E

    style B fill:#ff6b6b,color:#fff
    style C fill:#51cf66,color:#fff
```

## 1.2 Certificate Chain of Trust

```mermaid
flowchart TD
    ROOT["🏛️ Root CA<br/>CN=ISRG Root X1<br/>Self-signed<br/>Pre-installed in OS/browser trust stores<br/>Key: RSA 4096<br/>Validity: 2015-2035"]
    INT["🏢 Intermediate CA<br/>CN=R3<br/>Signed by Root<br/>Key: RSA 2048<br/>Validity: 2020-2025"]
    LEAF["📄 Leaf Certificate<br/>CN=api.example.com<br/>Signed by Intermediate<br/>Key: ECDSA P-256<br/>Validity: 90 days"]

    ROOT -->|"Signs<br/>(root key signs intermediate)"| INT
    INT -->|"Signs<br/>(intermediate key signs leaf)"| LEAF

    TRUST["🖥️ Client Trust Store<br/>Contains ~150 root CAs<br/>(pre-installed)"]
    TRUST -.->|"Trusts"| ROOT

    subgraph Verification["Client Verification Process"]
        V1["1. Server sends<br/>leaf + intermediate"]
        V2["2. Verify leaf signed<br/>by intermediate?"]
        V3["3. Verify intermediate<br/>signed by trusted root?"]
        V4["4. Check validity dates"]
        V5["5. Check revocation<br/>CRL/OCSP"]
        V6["6. Check SAN matches<br/>hostname"]
        V7["✅ TRUSTED"]

        V1 --> V2 --> V3 --> V4 --> V5 --> V6 --> V7
    end

    style ROOT fill:#e64980,color:#fff
    style INT fill:#be4bdb,color:#fff
    style LEAF fill:#4c6ef5,color:#fff
    style V7 fill:#51cf66,color:#fff
```

## 1.3 One-Way TLS Handshake (Standard HTTPS)

```mermaid
sequenceDiagram
    participant Client as 🖥️ Client (Browser)
    participant Server as 🌐 Server (api.example.com)

    Note over Client,Server: Standard TLS - Only SERVER is authenticated

    Client->>Server: 1. ClientHello
    Note right of Client: TLS version: 1.3<br/>Supported ciphers<br/>Client random (32 bytes)<br/>SNI: api.example.com

    Server->>Client: 2. ServerHello + Certificate
    Note left of Server: Selected cipher suite<br/>Server random<br/>📜 Certificate chain<br/>(leaf + intermediate)

    Note over Client: 3. Verify Certificate Chain
    Note over Client: ✅ Signatures valid?<br/>✅ Dates valid?<br/>✅ SAN matches hostname?<br/>✅ Not revoked?

    Client->>Server: 4. Key Exchange
    Note right of Client: ECDHE: Diffie-Hellman<br/>key agreement<br/>(or RSA key transport)

    Note over Client,Server: 5. Both derive session keys<br/>from shared secret

    Client->>Server: 6. Finished (encrypted)
    Server->>Client: 6. Finished (encrypted)

    rect rgb(200, 255, 200)
        Note over Client,Server: 🔒 Encrypted Application Data (AES-GCM)
        Client->>Server: HTTP Request
        Server->>Client: HTTP Response
    end

    Note over Client,Server: ⚠️ Only SERVER proved its identity<br/>Client is anonymous
```

## 1.4 ACME Protocol - Let's Encrypt Certificate Issuance

```mermaid
sequenceDiagram
    participant Admin as 👤 You (Server Admin)
    participant ACME as 🤖 ACME Client<br/>(certbot)
    participant LE as 🏛️ Let's Encrypt<br/>(ACME Server)
    participant DNS as 🌐 DNS / Web

    Note over Admin,DNS: ACME = Automatic Certificate Management Environment (RFC 8555)

    rect rgb(240, 240, 255)
        Note over ACME,LE: Phase 1: Account Registration (one-time)
        ACME->>ACME: Generate RSA 2048 account key pair
        ACME->>LE: POST /new-acct<br/>{email, termsOfServiceAgreed: true}
        LE-->>ACME: 201 Created<br/>Account URL: /acct/123
    end

    rect rgb(255, 240, 240)
        Note over ACME,LE: Phase 2: Order Certificate
        ACME->>LE: POST /new-order<br/>{identifiers: [{type:"dns", value:"api.example.com"}]}
        LE-->>ACME: 201 Created<br/>authorizations: [/authz/abc]<br/>finalize: /order/xyz/finalize
    end

    rect rgb(240, 255, 240)
        Note over ACME,DNS: Phase 3: Domain Validation (HTTP-01)
        ACME->>LE: GET /authz/abc
        LE-->>ACME: Challenges:<br/>HTTP-01: token=DGyRe...<br/>DNS-01: token=xKf3...

        ACME->>ACME: Compute key authorization:<br/>keyAuthz = token + "." + base64(SHA256(accountJWK))

        ACME->>DNS: Serve at:<br/>http://api.example.com/<br/>.well-known/acme-challenge/{token}<br/>Content: {keyAuthz}

        ACME->>LE: POST /challenge/{id}<br/>"I'm ready"

        LE->>DNS: GET http://api.example.com/<br/>.well-known/acme-challenge/{token}<br/>(from MULTIPLE vantage points)
        DNS-->>LE: 200 OK: {keyAuthz}

        LE->>LE: Verify token matches ✅
        LE-->>ACME: Challenge status: valid
    end

    rect rgb(255, 255, 230)
        Note over ACME,LE: Phase 4: Certificate Issuance
        ACME->>ACME: Generate ECDSA P-256 cert key pair<br/>Create CSR (public key + domain)
        Note over ACME: ⚠️ Private key NEVER<br/>leaves your server!

        ACME->>LE: POST /order/xyz/finalize<br/>{csr: base64url(DER)}
        LE->>LE: Sign certificate<br/>Add extensions<br/>90-day validity
        LE-->>ACME: Order status: valid<br/>certificate: /cert/abc123

        ACME->>LE: GET /cert/abc123
        LE-->>ACME: PEM certificate chain<br/>(leaf + intermediate)
    end

    ACME->>Admin: Certificate installed!<br/>fullchain.pem + privkey.pem

    Note over Admin,DNS: 🔄 Renewal: Repeat at day 60 (30 days before expiry)
```

## 1.5 ACME Challenge Types Comparison

```mermaid
flowchart TD
    START["Need a Certificate?"] --> Q1{"Wildcard<br/>*.example.com?"}

    Q1 -->|Yes| DNS01["DNS-01 Challenge<br/>(ONLY option for wildcards)"]
    Q1 -->|No| Q2{"Port 80<br/>available?"}

    Q2 -->|Yes| HTTP01["HTTP-01 Challenge<br/>(most common)"]
    Q2 -->|No| Q3{"Port 443<br/>available?"}

    Q3 -->|Yes| TLSALPN["TLS-ALPN-01 Challenge"]
    Q3 -->|No| DNS01

    HTTP01 --> H1["Serve token at:<br/>http://domain/.well-known/<br/>acme-challenge/{token}"]
    H1 --> H2["Let's Encrypt fetches URL<br/>from multiple locations"]
    H2 --> DONE["✅ Domain Validated"]

    DNS01 --> D1["Create TXT record:<br/>_acme-challenge.domain<br/>= base64(SHA256(keyAuthz))"]
    D1 --> D2["Let's Encrypt queries<br/>DNS for TXT record"]
    D2 --> DONE

    TLSALPN --> T1["Respond on :443 with<br/>special self-signed cert<br/>containing challenge token"]
    T1 --> T2["Let's Encrypt connects<br/>to :443 and verifies"]
    T2 --> DONE

    style HTTP01 fill:#4c6ef5,color:#fff
    style DNS01 fill:#be4bdb,color:#fff
    style TLSALPN fill:#f59f00,color:#000
    style DONE fill:#51cf66,color:#fff
```

## 1.6 Certificate Lifecycle

```mermaid
gantt
    title Certificate Lifecycle (Let's Encrypt - 90 day certs)
    dateFormat  YYYY-MM-DD
    axisFormat  Day %j

    section Certificate 1
    Valid Period           :active, cert1, 2025-01-01, 90d
    Renewal Window (day 60+) :crit, renew1, after cert1, 0d

    section Renewal
    Auto-renew triggered (day 60) :milestone, m1, 2025-03-02, 0d
    New cert issued              :milestone, m2, 2025-03-02, 0d

    section Certificate 2
    Valid Period           :active, cert2, 2025-03-02, 90d
    Overlap with cert 1   :done, overlap, 2025-03-02, 30d
```

```mermaid
sequenceDiagram
    participant Timer as ⏰ Renewal Timer
    participant ACME as 🤖 ACME Client
    participant LE as 🏛️ Let's Encrypt
    participant Server as 🌐 Your Server

    Note over Timer,Server: Day 0: Certificate issued (valid 90 days)

    Timer->>Timer: Wait until day 60...<br/>(30 days before expiry)

    Note over Timer,Server: Day 60: Auto-renewal triggered

    Timer->>ACME: Trigger renewal
    ACME->>LE: New order + challenge + CSR
    LE-->>ACME: New certificate (90 days)

    ACME->>Server: Hot-swap certificate<br/>(zero downtime)
    Note over Server: Old cert: valid until day 90<br/>New cert: valid for 90 more days

    Note over Timer,Server: Day 90: Old cert expires<br/>(but new cert already active since day 60)
```

## 1.7 Revocation Flow

```mermaid
sequenceDiagram
    participant Admin as 👤 Admin
    participant ACME as 🤖 ACME Client
    participant LE as 🏛️ Let's Encrypt
    participant OCSP as 📋 OCSP Responder
    participant Client as 🖥️ Client

    Note over Admin,Client: Private key compromised! Need to revoke.

    Admin->>ACME: Revoke certificate
    ACME->>LE: POST /revoke-cert<br/>(signed with account key<br/>or certificate key)
    LE->>LE: Mark cert as revoked
    LE->>OCSP: Update OCSP response<br/>& CRL (Certificate<br/>Revocation List)
    LE-->>ACME: 200 OK - Revoked

    Note over Client,OCSP: Later: Client connects to server with revoked cert

    Client->>OCSP: Is cert serial 0A1B2C revoked?<br/>(or check CRL)
    OCSP-->>Client: Status: REVOKED

    Client->>Client: ❌ Reject connection!

    Note over Client: OCSP Stapling (better approach):<br/>Server pre-fetches its own OCSP response<br/>and includes it in TLS handshake<br/>→ Faster, better privacy
```

## 1.8 RSA vs ECDSA Key Comparison

```mermaid
flowchart LR
    subgraph RSA["RSA-2048"]
        R1["Key Size: 2048 bits"]
        R2["Signature: ~256 bytes"]
        R3["Speed: Slower"]
        R4["Security: ~112-bit"]
        R5["Support: Universal"]
    end

    subgraph ECDSA["ECDSA P-256 ✅ Recommended"]
        E1["Key Size: 256 bits"]
        E2["Signature: ~64 bytes"]
        E3["Speed: Faster"]
        E4["Security: ~128-bit"]
        E5["Support: Growing"]
    end

    RSA ---|"Same security<br/>with 8x larger keys"| ECDSA

    style ECDSA fill:#d3f9d8,stroke:#51cf66
    style RSA fill:#fff3bf,stroke:#f59f00
```
