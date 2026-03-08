# 03 - mTLS Device-to-Service - Diagrams

## 3.1 Standard TLS vs mTLS

```mermaid
flowchart LR
    subgraph Standard_TLS["Standard TLS (one-way)"]
        C1["🖥️ Client<br/>(anonymous)"] -->|"Verifies server"| S1["🌐 Server<br/>(authenticated)"]
        S1 -.->|"Sends certificate"| C1
    end

    subgraph Mutual_TLS["Mutual TLS (two-way) ✅"]
        C2["📱 Device<br/>(authenticated)"] <-->|"Both verify<br/>each other"| S2["🌐 Server<br/>(authenticated)"]
    end

    style Standard_TLS fill:#fff3bf
    style Mutual_TLS fill:#d3f9d8
```

## 3.2 mTLS Handshake - Full Sequence

```mermaid
sequenceDiagram
    participant Device as 📱 Device (Client)
    participant Server as 🌐 Service (Server)

    Note over Device,Server: MUTUAL TLS Handshake - Both sides authenticate

    rect rgb(230, 240, 255)
        Note over Device,Server: Phase 1: Hello
        Device->>Server: ClientHello
        Note right of Device: TLS 1.3<br/>Supported ciphers<br/>SNI: api.iot.example.com

        Server->>Device: ServerHello + Certificate + CertificateRequest
        Note left of Server: Selected cipher<br/>📜 Server certificate chain<br/>📋 CertificateRequest:<br/>  acceptable_CAs: [<br/>    "Acme IoT Root CA",<br/>    "Acme IoT Intermediate CA"<br/>  ]<br/>  signature_algorithms: [<br/>    ecdsa_secp256r1_sha256<br/>  ]
    end

    rect rgb(255, 240, 230)
        Note over Device,Server: Phase 2: Server Authentication
        Device->>Device: Verify server certificate
        Note over Device: ✅ Chain valid (signed by trusted CA)?<br/>✅ SAN matches hostname?<br/>✅ Not expired?<br/>✅ Not revoked?
    end

    rect rgb(230, 255, 230)
        Note over Device,Server: Phase 3: Client (Device) Authentication - THE mTLS PART
        Device->>Server: Client Certificate + CertificateVerify
        Note right of Device: 📜 Device certificate chain<br/>✍️ CertificateVerify: signature<br/>   over handshake transcript<br/>   (proves possession of private key)

        Server->>Server: Verify device certificate
        Note over Server: ✅ Chain valid (signed by device CA)?<br/>✅ EKU has clientAuth?<br/>✅ Not expired / revoked?<br/>✅ Read metadata:<br/>  CN=device-042<br/>  OU=IoT-Sensors<br/>  SPIFFE=spiffe://cluster.local/...
    end

    rect rgb(240, 230, 255)
        Note over Device,Server: Phase 4: Key Exchange & Encrypted Channel
        Device->>Server: Finished (encrypted)
        Server->>Device: Finished (encrypted)
    end

    rect rgb(200, 255, 200)
        Note over Device,Server: 🔒 Both sides authenticated - Encrypted channel established
        Device->>Server: POST /api/telemetry<br/>{temp: 23.5, humidity: 65}
        Server->>Device: 200 OK<br/>{accepted: true, device: "device-042"}
    end
```

## 3.3 Device Certificate Provisioning - Factory Pattern

```mermaid
sequenceDiagram
    participant MCU as 🏭 Manufacturing<br/>Line
    participant TPM as 🔐 Device TPM<br/>/Secure Element
    participant PKI as 🏛️ Your CA / PKI

    Note over MCU,PKI: Pattern 1: Factory Provisioning

    MCU->>TPM: 1. Initialize secure element
    TPM->>TPM: 2. Generate key pair<br/>(inside TPM - private key<br/>NEVER leaves hardware)

    TPM->>MCU: 3. Return public key

    MCU->>MCU: 4. Create CSR<br/>CN=device-042<br/>OU=IoT-Sensors<br/>O=Acme Corp<br/>SERIALNUMBER=SN-2025-042

    MCU->>PKI: 5. Submit CSR
    PKI->>PKI: 6. Validate CSR<br/>Sign certificate
    PKI-->>MCU: 7. Return signed certificate

    MCU->>TPM: 8. Store certificate<br/>(alongside private key)

    MCU->>MCU: 9. Store CA chain<br/>(for server verification)

    Note over MCU,PKI: Device ships with:<br/>🔑 Private key (in TPM, non-exportable)<br/>📜 Device certificate (signed by CA)<br/>📜 CA certificate chain
```

## 3.4 Device Certificate Provisioning - Enrollment/Bootstrap Pattern

```mermaid
sequenceDiagram
    participant Device as 📱 New Device
    participant Enroll as 🔑 Enrollment<br/>Service
    participant CA as 🏛️ Your CA
    participant Registry as 📋 Device<br/>Registry

    Note over Device,Registry: Pattern 2: Bootstrap Enrollment

    Device->>Device: 1. Has bootstrap credential<br/>(one-time token from factory<br/>or manufacturer cert)

    Device->>Enroll: 2. Connect with bootstrap token
    Note right of Device: "I'm new, here's my<br/>one-time enrollment token"

    Enroll->>Registry: 3. Validate token
    Registry-->>Enroll: 4. Token valid for device-042

    Enroll->>Enroll: 5. Tell device to generate key pair

    Device->>Device: 6. Generate key pair
    Device->>Enroll: 7. Send CSR (public key + identity)

    Enroll->>CA: 8. Request cert for device-042
    CA-->>Enroll: 9. Signed certificate

    Enroll-->>Device: 10. Here's your certificate + CA chain
    Enroll->>Registry: 11. Register device-042 as enrolled

    Device->>Device: 12. Store cert<br/>13. DELETE bootstrap token<br/>(single use!)

    Note over Device,Registry: Future connections use device cert for mTLS
```

## 3.5 Architecture Pattern A: Direct mTLS

```mermaid
flowchart LR
    D1["📱 Device 1<br/>cert: CN=dev-001<br/>OU=Sensors"] <-->|"mTLS"| S["🌐 Service<br/>Validates device cert<br/>Reads metadata<br/>Applies RBAC"]
    D2["📱 Device 2<br/>cert: CN=dev-002<br/>OU=Actuators"] <-->|"mTLS"| S
    D3["📱 Device 3<br/>cert: CN=dev-003<br/>OU=Admin"] <-->|"mTLS"| S

    S --> AUTH{"Authorization<br/>based on OU"}
    AUTH -->|Sensors| TELEM["✅ /telemetry"]
    AUTH -->|Actuators| CMD["✅ /commands"]
    AUTH -->|Admin| ADMIN["✅ /admin"]

    style S fill:#4c6ef5,color:#fff
```

## 3.6 Architecture Pattern B: mTLS Gateway

```mermaid
flowchart LR
    D1["📱 Device 1"] <-->|"mTLS"| GW["🚪 API Gateway<br/>───────────<br/>Terminates mTLS<br/>Validates cert<br/>Extracts metadata<br/>Adds headers:<br/>X-Device-ID<br/>X-Device-Fleet<br/>X-Device-OU"]
    D2["📱 Device 2"] <-->|"mTLS"| GW
    D3["📱 Device 3"] <-->|"mTLS"| GW

    GW -->|"HTTP + headers<br/>(internal network)"| S1["🌐 Service A<br/>Reads X-Device-ID<br/>from header"]
    GW -->|"HTTP + headers"| S2["🌐 Service B"]
    GW -->|"HTTP + headers"| S3["🌐 Service C"]

    style GW fill:#be4bdb,color:#fff
```

## 3.7 Architecture Pattern C: Service Mesh (Dapr/Istio)

```mermaid
flowchart LR
    subgraph Pod_A["Pod A"]
        A["🌐 Service A<br/>(plain HTTP)"] <--> SA["🛡️ Dapr Sidecar<br/>SPIFFE: ...svc-a"]
    end

    subgraph Pod_B["Pod B"]
        B["🌐 Service B<br/>(plain HTTP)"] <--> SB["🛡️ Dapr Sidecar<br/>SPIFFE: ...svc-b"]
    end

    subgraph Pod_C["Pod C"]
        C["🌐 Service C<br/>(plain HTTP)"] <--> SC["🛡️ Dapr Sidecar<br/>SPIFFE: ...svc-c"]
    end

    SA <-->|"🔒 mTLS<br/>(automatic)"| SB
    SA <-->|"🔒 mTLS<br/>(automatic)"| SC
    SB <-->|"🔒 mTLS<br/>(automatic)"| SC

    style A fill:#51cf66,color:#fff
    style B fill:#51cf66,color:#fff
    style C fill:#51cf66,color:#fff
    style SA fill:#4c6ef5,color:#fff
    style SB fill:#4c6ef5,color:#fff
    style SC fill:#4c6ef5,color:#fff
```

## 3.8 Certificate Pinning vs Chain Validation

```mermaid
flowchart TD
    subgraph Chain["Chain Validation ✅ Scales"]
        CV_IN["Incoming cert"]
        CV_CHECK{"Signed by<br/>trusted CA?"}
        CV_IN --> CV_CHECK
        CV_CHECK -->|Yes| CV_TRUST["✅ Trusted<br/>(any cert from CA)"]
        CV_CHECK -->|No| CV_DENY["❌ Rejected"]
        CV_NOTE["Auto-trusts new devices<br/>if signed by same CA"]
    end

    subgraph Pin["Certificate Pinning 🔒 Max Control"]
        PIN_IN["Incoming cert"]
        PIN_CHECK{"Thumbprint in<br/>allowlist?"}
        PIN_IN --> PIN_CHECK
        PIN_CHECK -->|Yes| PIN_TRUST["✅ Trusted<br/>(specific cert only)"]
        PIN_CHECK -->|No| PIN_DENY["❌ Rejected<br/>(even if CA is valid!)"]
        PIN_NOTE["Must register each<br/>device individually"]
    end

    subgraph Hybrid["Hybrid ✅ Recommended"]
        HY_IN["Incoming cert"]
        HY_CHAIN{"1. Chain<br/>valid?"}
        HY_REG{"2. Device in<br/>registry?"}
        HY_DENY_LIST{"3. On deny<br/>list?"}
        HY_IN --> HY_CHAIN
        HY_CHAIN -->|No| HY_DENY1["❌"]
        HY_CHAIN -->|Yes| HY_REG
        HY_REG -->|No| HY_DENY2["❌ Unknown device"]
        HY_REG -->|Yes| HY_DENY_LIST
        HY_DENY_LIST -->|Yes| HY_DENY3["❌ Revoked"]
        HY_DENY_LIST -->|No| HY_TRUST["✅ Trusted"]
    end

    style Chain fill:#e7f5ff
    style Pin fill:#fff3bf
    style Hybrid fill:#d3f9d8
```
