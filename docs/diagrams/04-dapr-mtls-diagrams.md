# 04 - Dapr mTLS Architecture - Diagrams

## 4.1 Dapr Sidecar Architecture Overview

```mermaid
flowchart TD
    subgraph Cluster["Kubernetes Cluster"]

        subgraph Control["Dapr Control Plane (dapr-system namespace)"]
            SENTRY["🏛️ Dapr Sentry<br/>Certificate Authority<br/>─────────<br/>Issues workload certs<br/>Manages trust domain<br/>Root cert (self-signed<br/>or from cert-manager)"]
            OPERATOR["⚙️ Dapr Operator<br/>Manages components"]
            INJECTOR["💉 Sidecar Injector<br/>MutatingWebhook<br/>Auto-injects daprd"]
        end

        subgraph AppNS["Application Namespace"]
            subgraph PodA["Pod: order-service"]
                APP_A["🌐 .NET App<br/>Port 5000<br/>Plain HTTP<br/>NO TLS code!"]
                SIDE_A["🛡️ Dapr Sidecar<br/>(daprd)<br/>Port 3500 (HTTP)<br/>Port 50001 (gRPC)<br/>─────────<br/>Workload cert in memory<br/>SPIFFE: spiffe://cluster.local<br/>/ns/default/order-service"]
                APP_A <-->|"localhost<br/>HTTP"| SIDE_A
            end

            subgraph PodB["Pod: payment-service"]
                APP_B["🌐 .NET App<br/>Port 5000"]
                SIDE_B["🛡️ Dapr Sidecar<br/>SPIFFE: .../payment-service"]
                APP_B <-->|"localhost"| SIDE_B
            end
        end

        SENTRY -->|"Signs workload<br/>certs"| SIDE_A
        SENTRY -->|"Signs workload<br/>certs"| SIDE_B
        INJECTOR -.->|"Injects sidecar<br/>into pods"| PodA
        INJECTOR -.->|"Injects"| PodB
        SIDE_A <-->|"🔒 mTLS<br/>(automatic)"| SIDE_B
    end

    style SENTRY fill:#e64980,color:#fff
    style SIDE_A fill:#4c6ef5,color:#fff
    style SIDE_B fill:#4c6ef5,color:#fff
    style APP_A fill:#51cf66,color:#fff
    style APP_B fill:#51cf66,color:#fff
```

## 4.2 Sentry Certificate Signing Flow

```mermaid
sequenceDiagram
    participant Pod as 📦 Pod Starts
    participant Sidecar as 🛡️ Dapr Sidecar<br/>(daprd)
    participant K8s as ☸️ Kubernetes API
    participant Sentry as 🏛️ Dapr Sentry<br/>(CA)

    Note over Pod,Sentry: Sidecar startup and certificate provisioning

    Pod->>Sidecar: 1. Pod starts, sidecar injected

    Sidecar->>Sidecar: 2. Generate ECDSA P-256 key pair<br/>(private key stays in MEMORY)

    Sidecar->>Sidecar: 3. Create CSR<br/>- app-id: "order-service"<br/>- namespace: "default"<br/>- trust domain: "cluster.local"

    Sidecar->>K8s: 4. Get ServiceAccount token<br/>(from mounted secret)
    K8s-->>Sidecar: 5. SA token (JWT)

    Sidecar->>Sentry: 6. gRPC: SignCertificate(CSR + SA token)

    Sentry->>K8s: 7. Validate SA token<br/>(TokenReview API)
    K8s-->>Sentry: 8. Token valid for<br/>SA "order-service"<br/>in namespace "default"

    Sentry->>Sentry: 9. Build certificate:<br/>Subject: O=dapr.io, CN=cluster.local<br/>SAN URI: spiffe://cluster.local<br/>  /ns/default/order-service<br/>EKU: serverAuth + clientAuth<br/>Validity: 24 hours<br/>Key Usage: digitalSignature

    Sentry->>Sentry: 10. Sign with Sentry's root key

    Sentry-->>Sidecar: 11. Signed workload cert<br/>+ trust chain (CA cert)

    Sidecar->>Sidecar: 12. Store cert + key in MEMORY<br/>(never written to disk!)

    Note over Sidecar: 13. Ready for mTLS connections!

    Note over Sidecar,Sentry: 🔄 Rotation: At 70% of TTL (~17 hours),<br/>sidecar generates NEW key pair and repeats steps 2-12
```

## 4.3 SPIFFE Identity in Dapr

```mermaid
flowchart TD
    SPIFFE["SPIFFE ID in Certificate SAN"]
    SPIFFE --> FORMAT["Format:<br/>spiffe://{trust-domain}/ns/{namespace}/{app-id}"]

    FORMAT --> EX1["spiffe://cluster.local/ns/default/order-service"]
    FORMAT --> EX2["spiffe://cluster.local/ns/production/payment-service"]
    FORMAT --> EX3["spiffe://cluster.local/ns/staging/order-service"]

    EX1 --> PARTS1["Trust Domain: cluster.local<br/>Namespace: default<br/>App ID: order-service"]
    EX2 --> PARTS2["Trust Domain: cluster.local<br/>Namespace: production<br/>App ID: payment-service"]

    subgraph Trust["Same Trust Domain = Can Communicate"]
        T1["All services signed by<br/>same Sentry root CA"]
        T2["Access control policies<br/>determine who can call whom"]
    end

    PARTS1 --> Trust
    PARTS2 --> Trust

    style SPIFFE fill:#4c6ef5,color:#fff
    style Trust fill:#d3f9d8
```

## 4.4 Workload Certificate Contents

```mermaid
flowchart TD
    CERT["📜 Dapr Workload Certificate"]

    CERT --> BASIC["Version: 3<br/>Serial: random<br/>Issuer: O=dapr.io, CN=cluster.local<br/>Subject: O=dapr.io, CN=cluster.local"]

    CERT --> VALIDITY["Validity:<br/>Not Before: 2025-01-15T10:00:00Z<br/>Not After:  2025-01-16T10:00:00Z<br/>─────────<br/>⏱️ Only 24 hours!<br/>(reduces compromise window)"]

    CERT --> SAN_BLOCK["Subject Alternative Names:<br/>URI: spiffe://cluster.local<br/>     /ns/default/order-service<br/>DNS: order-service.default<br/>     .svc.cluster.local"]

    CERT --> EXT_BLOCK["Key Usage: digitalSignature<br/>Extended Key Usage:<br/>  serverAuth + clientAuth<br/>Basic Constraints: CA:FALSE"]

    CERT --> DESIGN["Design Decisions:<br/>✅ 24h validity (short-lived)<br/>✅ In-memory only (no disk)<br/>✅ SPIFFE URI (standard identity)<br/>✅ Both server+client auth<br/>✅ Auto-rotated at 70%"]

    style CERT fill:#4c6ef5,color:#fff
    style VALIDITY fill:#f59f00,color:#000
    style DESIGN fill:#51cf66,color:#fff
```

## 4.5 Certificate Auto-Rotation Timeline

```mermaid
gantt
    title Dapr Workload Certificate Rotation (24h TTL)
    dateFormat HH:mm
    axisFormat %H:%M

    section Cert 1
    Valid (24h)              :active, c1, 00:00, 24h
    Rotation trigger (70%)   :crit, r1, 16:48, 0h

    section Cert 2
    Valid (24h)              :active, c2, 16:48, 24h
    Overlap with Cert 1      :done, o1, 16:48, 7h
```

```mermaid
sequenceDiagram
    participant Timer as ⏰ Rotation Timer
    participant Sidecar as 🛡️ Sidecar
    participant Sentry as 🏛️ Sentry

    Note over Timer,Sentry: Hour 0: Certificate issued (24h TTL)

    Timer->>Timer: Wait until 70% of TTL...<br/>(~16h 48min)

    Note over Timer,Sentry: Hour 16:48 - Rotation triggered

    Sidecar->>Sidecar: 1. Generate NEW key pair
    Sidecar->>Sentry: 2. New CSR + SA token
    Sentry-->>Sidecar: 3. New signed cert

    Sidecar->>Sidecar: 4. ATOMIC SWAP:<br/>- Old cert still valid (7h left)<br/>- New cert now active<br/>- Old connections continue<br/>- New connections use new cert

    Note over Timer,Sentry: Zero downtime! 🎉

    Note over Timer,Sentry: Hour 24: Old cert expires<br/>(new cert has been active for 7h)
```

## 4.6 Dapr Service Invocation with mTLS

```mermaid
sequenceDiagram
    participant AppA as 🌐 .NET App A<br/>(order-service)
    participant SideA as 🛡️ Sidecar A
    participant DNS as 📡 Name Resolution<br/>(K8s DNS / mDNS)
    participant SideB as 🛡️ Sidecar B
    participant AppB as 🌐 .NET App B<br/>(payment-service)

    AppA->>SideA: 1. HTTP POST localhost:3500<br/>/v1.0/invoke/payment-service<br/>/method/process<br/>Body: {orderId: 1, amount: 99.99}

    SideA->>DNS: 2. Resolve "payment-service"
    DNS-->>SideA: 3. 10.96.45.123:50001

    rect rgb(255, 230, 230)
        Note over SideA,SideB: 4. mTLS Handshake (automatic)
        SideA->>SideB: ClientHello + Sidecar A's cert<br/>SPIFFE: .../order-service
        SideB->>SideA: ServerHello + Sidecar B's cert<br/>SPIFFE: .../payment-service
        SideB->>SideB: 5. Verify A's cert chain ✅<br/>Read SPIFFE ID ✅<br/>Check access policy ✅
        SideA->>SideA: 5. Verify B's cert chain ✅
    end

    SideA->>SideB: 6. Forward request<br/>(encrypted gRPC)

    SideB->>AppB: 7. localhost:5000<br/>POST /process<br/>(plain HTTP)

    AppB->>AppB: 8. Process payment
    AppB-->>SideB: 9. Response: {success: true}

    SideB-->>SideA: 10. Response (encrypted)
    SideA-->>AppA: 11. Response to app<br/>{success: true}

    Note over AppA,AppB: Your .NET code: ZERO mTLS logic<br/>Just call DaprClient.InvokeMethodAsync()
```

## 4.7 Dapr Access Control Policy Enforcement

```mermaid
flowchart TD
    REQ["📨 Incoming mTLS request<br/>from Sidecar A"]

    REQ --> EXTRACT["Extract SPIFFE ID from client cert<br/>spiffe://cluster.local/ns/default/order-service"]

    EXTRACT --> PARSE["Parse identity:<br/>trust-domain: cluster.local<br/>namespace: default<br/>app-id: order-service"]

    PARSE --> MATCH{"Match against<br/>access control policies"}

    MATCH --> FIND{"Policy found for<br/>appId: order-service?"}
    FIND -->|No| DEFAULT{"Default action?"}
    DEFAULT -->|deny| DENY1["❌ 403 Forbidden"]
    DEFAULT -->|allow| ALLOW_ALL["✅ Allow (not recommended)"]

    FIND -->|Yes| CHECK_TD{"Trust domain<br/>matches?"}
    CHECK_TD -->|No| DENY2["❌ 403 Wrong trust domain"]
    CHECK_TD -->|Yes| CHECK_NS{"Namespace<br/>matches?"}
    CHECK_NS -->|No| DENY3["❌ 403 Wrong namespace"]
    CHECK_NS -->|Yes| CHECK_OP{"Operation allowed?<br/>POST /process-payment"}
    CHECK_OP -->|No match| DENY4["❌ 403 Operation denied"]
    CHECK_OP -->|Match + allow| ALLOW["✅ Forward to app"]

    style REQ fill:#4c6ef5,color:#fff
    style ALLOW fill:#51cf66,color:#fff
    style DENY1 fill:#ff6b6b,color:#fff
    style DENY2 fill:#ff6b6b,color:#fff
    style DENY3 fill:#ff6b6b,color:#fff
    style DENY4 fill:#ff6b6b,color:#fff
```

## 4.8 Dapr Trust Hierarchy

```mermaid
flowchart TD
    subgraph TrustDomain["Trust Domain: cluster.local"]
        ROOT["🏛️ Sentry Root CA<br/>O=dapr.io<br/>CN=cluster.local<br/>─────────<br/>Self-signed or<br/>from cert-manager"]

        ROOT -->|Signs| W1["📜 Workload Cert<br/>order-service<br/>ns: default<br/>TTL: 24h"]
        ROOT -->|Signs| W2["📜 Workload Cert<br/>payment-service<br/>ns: default<br/>TTL: 24h"]
        ROOT -->|Signs| W3["📜 Workload Cert<br/>inventory-service<br/>ns: production<br/>TTL: 24h"]
        ROOT -->|Signs| W4["📜 Workload Cert<br/>order-service<br/>ns: staging<br/>TTL: 24h"]

        W1 <-->|"mTLS ✅"| W2
        W1 <-->|"mTLS ✅<br/>(cross-namespace)"| W3
        W2 <-->|"mTLS ✅"| W3
    end

    OTHER["📜 Cert from different<br/>trust domain<br/>(or unknown CA)"]
    OTHER -->|"mTLS ❌<br/>Untrusted!"| W1

    style ROOT fill:#e64980,color:#fff
    style W1 fill:#4c6ef5,color:#fff
    style W2 fill:#4c6ef5,color:#fff
    style W3 fill:#be4bdb,color:#fff
    style W4 fill:#f59f00,color:#000
    style OTHER fill:#ff6b6b,color:#fff
```

## 4.9 Kubernetes vs Self-Hosted Dapr

```mermaid
flowchart LR
    subgraph K8s["Kubernetes Mode"]
        K_SENTRY["Sentry<br/>K8s Deployment"]
        K_SECRET["Root cert in<br/>K8s Secret:<br/>dapr-trust-bundle"]
        K_SA["SA Token validation<br/>via K8s API"]
        K_DNS["Name resolution<br/>via K8s DNS"]
        K_INJECT["Auto-injection<br/>via Webhook"]

        K_SENTRY --- K_SECRET
        K_SENTRY --- K_SA
        K_SENTRY --- K_DNS
        K_SENTRY --- K_INJECT
    end

    subgraph Self["Self-Hosted Mode"]
        S_SENTRY["Sentry<br/>Standalone process"]
        S_FILE["Root cert in<br/>~/.dapr/certs/"]
        S_TRUST["Shared trust<br/>bundle"]
        S_MDNS["Name resolution<br/>via mDNS"]
        S_MANUAL["Manual sidecar<br/>via dapr run"]

        S_SENTRY --- S_FILE
        S_SENTRY --- S_TRUST
        S_SENTRY --- S_MDNS
        S_SENTRY --- S_MANUAL
    end

    style K8s fill:#e7f5ff
    style Self fill:#fff3bf
```
