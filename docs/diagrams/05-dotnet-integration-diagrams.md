# 05 - .NET Integration - Diagrams

## 5.1 ASP.NET Core mTLS Request Pipeline

```mermaid
flowchart TD
    REQ["📨 Incoming HTTPS Request<br/>(with client certificate)"]

    REQ --> KESTREL["🌐 Kestrel Web Server<br/>Port 5001 HTTPS"]

    KESTREL --> TLS_HAND["TLS Handshake"]
    TLS_HAND --> SERVER_CERT["1. Present server.pfx<br/>to client"]
    SERVER_CERT --> REQUEST_CLIENT["2. Send CertificateRequest<br/>(list of acceptable CAs)"]
    REQUEST_CLIENT --> RECEIVE_CLIENT["3. Receive client certificate"]
    RECEIVE_CLIENT --> VALIDATE_BASIC["4. Basic TLS validation<br/>ClientCertificateValidation callback"]

    VALIDATE_BASIC -->|"Fail"| REJECT_TLS["❌ TLS Handshake Failed<br/>(connection dropped)"]
    VALIDATE_BASIC -->|"Pass"| HTTP_PIPELINE["HTTP Pipeline begins"]

    HTTP_PIPELINE --> AUTH_MW["🔐 Authentication Middleware<br/>CertificateAuthenticationDefaults"]

    AUTH_MW --> CHAIN_CHECK["Chain Validation<br/>CustomRootTrust: ca.crt"]
    CHAIN_CHECK -->|"Invalid"| AUTH_FAIL["❌ 401 Unauthorized"]
    CHAIN_CHECK -->|"Valid"| ON_VALIDATED["OnCertificateValidated Event"]

    ON_VALIDATED --> READ_META["Read Certificate Metadata<br/>CN, OU, O, SERIALNUMBER<br/>SAN, EKU, Thumbprint"]

    READ_META --> SEC_CHECKS["Security Checks:<br/>✅ Has clientAuth EKU?<br/>✅ Not a CA cert?<br/>✅ In device registry?"]
    SEC_CHECKS -->|"Fail"| AUTH_FAIL2["❌ 401 - Security check failed"]

    SEC_CHECKS -->|"Pass"| BUILD_CLAIMS["Build ClaimsPrincipal<br/>Claims from cert fields:<br/>device-id ← CN<br/>device-fleet ← OU<br/>Role ← OU mapping<br/>cert-thumbprint<br/>cert-issuer"]

    BUILD_CLAIMS --> AUTHZ_MW["🛡️ Authorization Middleware"]

    AUTHZ_MW --> POLICY_CHECK{"Check Policy<br/>for endpoint"}
    POLICY_CHECK -->|"SensorsAllowed"| ROLE_CHECK1{"Role == sensor<br/>or admin?"}
    POLICY_CHECK -->|"AdminOnly"| ROLE_CHECK2{"Role == admin?"}
    POLICY_CHECK -->|"AnyDevice"| ROLE_CHECK3{"Authenticated?"}

    ROLE_CHECK1 -->|No| FORBID["❌ 403 Forbidden"]
    ROLE_CHECK1 -->|Yes| ENDPOINT
    ROLE_CHECK2 -->|No| FORBID
    ROLE_CHECK2 -->|Yes| ENDPOINT
    ROLE_CHECK3 -->|No| FORBID
    ROLE_CHECK3 -->|Yes| ENDPOINT

    ENDPOINT["✅ Endpoint Handler<br/>Access HttpContext.User claims<br/>Process request"]

    style REQ fill:#4c6ef5,color:#fff
    style AUTH_MW fill:#be4bdb,color:#fff
    style AUTHZ_MW fill:#f59f00,color:#000
    style ENDPOINT fill:#51cf66,color:#fff
    style REJECT_TLS fill:#ff6b6b,color:#fff
    style AUTH_FAIL fill:#ff6b6b,color:#fff
    style AUTH_FAIL2 fill:#ff6b6b,color:#fff
    style FORBID fill:#ff6b6b,color:#fff
```

## 5.2 Certificate OU → Role Mapping

```mermaid
flowchart LR
    CERT["Client Certificate<br/>Subject.OU"] --> SWITCH{"OU Value?"}

    SWITCH -->|"IoT-Sensors"| SENSOR["Role: sensor"]
    SWITCH -->|"IoT-Actuators"| ACTUATOR["Role: actuator"]
    SWITCH -->|"IoT-Admin"| ADMIN["Role: admin"]
    SWITCH -->|"Backend-Services"| SERVICE["Role: service"]
    SWITCH -->|"unknown"| UNKNOWN["Role: unknown"]

    SENSOR --> P1["✅ POST /telemetry<br/>❌ POST /commands<br/>❌ GET /admin"]
    ACTUATOR --> P2["✅ POST /telemetry<br/>✅ POST /commands<br/>❌ GET /admin"]
    ADMIN --> P3["✅ POST /telemetry<br/>✅ POST /commands<br/>✅ GET /admin"]
    UNKNOWN --> P4["❌ All endpoints denied"]

    style SENSOR fill:#51cf66,color:#fff
    style ACTUATOR fill:#4c6ef5,color:#fff
    style ADMIN fill:#be4bdb,color:#fff
    style UNKNOWN fill:#ff6b6b,color:#fff
```

## 5.3 .NET HttpClient mTLS Configuration

```mermaid
sequenceDiagram
    participant App as 🌐 .NET Client App
    participant Handler as 🔧 HttpClientHandler
    participant TLS as 🔒 TLS Layer
    participant Server as 🌐 mTLS Server

    App->>Handler: 1. Create HttpClientHandler

    App->>Handler: 2. handler.ClientCertificates.Add(clientCert)<br/>(load from PFX file)

    App->>Handler: 3. Set ServerCertificateCustomValidationCallback<br/>(custom trust store with our CA)

    App->>App: 4. var client = new HttpClient(handler)

    App->>TLS: 5. client.GetAsync("https://localhost:5001/api/info")

    TLS->>Server: 6. TLS ClientHello

    Server->>TLS: 7. ServerHello + Server cert + CertificateRequest

    TLS->>TLS: 8. ServerCertificateCustomValidationCallback<br/>→ Build chain with custom CA<br/>→ Returns true/false

    TLS->>Server: 9. Client Certificate (from ClientCertificates)<br/>+ CertificateVerify

    Server->>Server: 10. Validate client cert

    rect rgb(200, 255, 200)
        Server-->>TLS: 11. HTTP Response
        TLS-->>App: 12. HttpResponseMessage
    end
```

## 5.4 .NET Dapr SDK Flow (Zero mTLS Code)

```mermaid
sequenceDiagram
    participant App as 🌐 Your .NET App<br/>Port 5000
    participant SDK as 📦 Dapr SDK<br/>(DaprClient)
    participant Sidecar as 🛡️ Dapr Sidecar<br/>Port 3500/50001
    participant Remote as 🛡️ Remote Sidecar
    participant Target as 🌐 Target Service

    Note over App,Target: Your code has ZERO TLS logic

    App->>SDK: await dapr.InvokeMethodAsync<br/>("payment-service", "process", order)

    SDK->>Sidecar: HTTP POST localhost:3500<br/>/v1.0/invoke/payment-service/method/process<br/>(plain HTTP to localhost!)

    Note over Sidecar,Remote: Sidecar handles everything

    Sidecar->>Sidecar: Resolve "payment-service"<br/>(Kubernetes DNS)

    rect rgb(255, 230, 230)
        Note over Sidecar,Remote: mTLS (automatic - your code doesn't know)
        Sidecar->>Remote: Encrypted gRPC with mTLS<br/>Presents workload cert<br/>Verifies remote cert<br/>Checks access policy
    end

    Remote->>Target: localhost:5000<br/>POST /process<br/>(plain HTTP)

    Target-->>Remote: Response
    Remote-->>Sidecar: Encrypted response
    Sidecar-->>SDK: HTTP response
    SDK-->>App: PaymentResult object
```

## 5.5 Certificate Loading in .NET - All Sources

```mermaid
flowchart TD
    LOAD["Load Certificate in .NET"]

    LOAD --> PFX["📄 PFX File<br/>new X509Certificate2(<br/>'cert.pfx', 'password')"]
    LOAD --> PEM["📄 PEM Files (.NET 8+)<br/>X509Certificate2.CreateFromPemFile(<br/>'cert.pem', 'key.pem')"]
    LOAD --> STORE["🗄️ Windows Cert Store<br/>X509Store + Find()"]
    LOAD --> K8S["☸️ Kubernetes Secret<br/>File.ReadAllBytes(<br/>'/var/run/secrets/tls/tls.crt')"]
    LOAD --> AKV["☁️ Azure Key Vault<br/>CertificateClient<br/>.DownloadCertificateAsync()"]
    LOAD --> STR["📝 PEM String (.NET 8+)<br/>X509Certificate2.CreateFromPem(<br/>certPem, keyPem)"]

    PFX --> USE["X509Certificate2 ready to use"]
    PEM --> USE
    STORE --> USE
    K8S --> USE
    AKV --> USE
    STR --> USE

    USE --> SERVER_USE["🌐 Kestrel Server<br/>httpsOptions.ServerCertificate = cert"]
    USE --> CLIENT_USE["📡 HttpClient<br/>handler.ClientCertificates.Add(cert)"]
    USE --> READ_USE["🔍 Inspect<br/>cert.Subject, cert.Thumbprint, etc."]

    style PFX fill:#be4bdb,color:#fff
    style PEM fill:#4c6ef5,color:#fff
    style K8S fill:#51cf66,color:#fff
    style AKV fill:#339af0,color:#fff
```

## 5.6 Complete .NET mTLS Demo Architecture

```mermaid
flowchart TD
    subgraph GenCerts["Step 1: Generate Certificates"]
        SCRIPT["🔧 generate-certs.sh<br/>or<br/>python acme_certificate.py local"]
        SCRIPT --> CA_CRT["📜 ca.crt<br/>Root CA"]
        SCRIPT --> SERVER_PFX["📜 server.pfx<br/>Server cert + key<br/>pass: server123"]
        SCRIPT --> CLIENT_PFX["📜 client.pfx<br/>Client cert + key<br/>pass: client123"]
    end

    subgraph Server["Step 2: MtlsServer (port 5001)"]
        S_KESTREL["Kestrel loads server.pfx<br/>ClientCertificateMode: RequireCertificate"]
        S_TRUST["Custom trust store: ca.crt<br/>(only trust our CA)"]
        S_AUTH["Cert auth middleware:<br/>→ Validate chain<br/>→ Read metadata<br/>→ Build Claims<br/>→ Map OU to Role"]
        S_ENDPOINTS["Endpoints:<br/>GET /api/device-info<br/>POST /api/telemetry<br/>POST /api/commands<br/>GET /api/admin/status<br/>GET /api/cert-chain"]
    end

    subgraph Client["Step 3: MtlsClient"]
        C_LOAD["Load client.pfx"]
        C_TRUST["Trust store: ca.crt"]
        C_HANDLER["HttpClientHandler:<br/>+ ClientCertificates<br/>+ ServerCertValidation"]
        C_CALL["Call server endpoints<br/>Shows responses + metadata"]
    end

    CA_CRT --> S_TRUST
    SERVER_PFX --> S_KESTREL
    CA_CRT --> C_TRUST
    CLIENT_PFX --> C_LOAD

    C_HANDLER <-->|"🔒 mTLS"| S_KESTREL

    style GenCerts fill:#fff3bf
    style Server fill:#e7f5ff
    style Client fill:#d3f9d8
```
