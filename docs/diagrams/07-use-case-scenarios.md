# 07 - End-to-End Use Case Scenarios - Diagrams

## Use Case 1: IoT Fleet Management with mTLS

### Scenario
A company manages 10,000 IoT temperature sensors deployed across multiple factories.
Each sensor authenticates to the cloud backend using mTLS certificates.

```mermaid
flowchart TD
    subgraph Factory_East["Factory East"]
        S1["🌡️ Sensor 001<br/>CN=sensor-001<br/>OU=Fleet-East<br/>O=Acme Corp"]
        S2["🌡️ Sensor 002<br/>CN=sensor-002<br/>OU=Fleet-East"]
        S3["🌡️ ... 2,000 sensors"]
    end

    subgraph Factory_West["Factory West"]
        S4["🌡️ Sensor 5001<br/>CN=sensor-5001<br/>OU=Fleet-West"]
        S5["🌡️ ... 3,000 sensors"]
    end

    subgraph Cloud["Cloud Backend (Kubernetes)"]
        INGRESS["🚪 Ingress<br/>TLS: Let's Encrypt cert<br/>(cert-manager)"]

        subgraph MtlsGateway["mTLS API Gateway"]
            GW["Terminates mTLS<br/>Validates device cert<br/>Extracts identity<br/>from cert metadata"]
        end

        subgraph Services["Microservices (Dapr mTLS)"]
            TELEMETRY["📊 Telemetry Service<br/>Accepts POST /data"]
            REGISTRY["📋 Device Registry<br/>Tracks all devices"]
            ALERTS["🚨 Alert Service<br/>Anomaly detection"]
        end

        subgraph Storage["Data Layer"]
            TSDB["📈 Time Series DB"]
            REDIS["🗄️ Redis (State)"]
        end
    end

    S1 & S2 & S3 -->|"mTLS<br/>(device certs)"| GW
    S4 & S5 -->|"mTLS<br/>(device certs)"| GW

    GW -->|"X-Device-ID: sensor-001<br/>X-Fleet: Fleet-East"| TELEMETRY
    TELEMETRY <-->|"Dapr mTLS"| REGISTRY
    TELEMETRY <-->|"Dapr mTLS"| ALERTS
    TELEMETRY --> TSDB
    REGISTRY --> REDIS

    style Factory_East fill:#e7f5ff
    style Factory_West fill:#fff3bf
    style MtlsGateway fill:#f3f0ff
    style Services fill:#d3f9d8
```

### Certificate-Based Routing Decision

```mermaid
sequenceDiagram
    participant Sensor as 🌡️ Sensor-001
    participant GW as 🚪 mTLS Gateway
    participant East as 📊 East Telemetry<br/>(US-East region)
    participant West as 📊 West Telemetry<br/>(US-West region)
    participant Registry as 📋 Device Registry

    Sensor->>GW: mTLS connection + POST /telemetry<br/>{temp: 23.5, humidity: 65}

    GW->>GW: Read client certificate:<br/>CN=sensor-001<br/>OU=Fleet-East<br/>O=Acme Corp<br/>SERIALNUMBER=SN-2025-001

    GW->>Registry: Is sensor-001 registered?
    Registry-->>GW: ✅ Active, Fleet-East, role=sensor

    GW->>GW: Route based on OU:<br/>Fleet-East → East region<br/>Fleet-West → West region

    GW->>East: Forward telemetry<br/>+ device context headers

    East-->>GW: 200 OK
    GW-->>Sensor: 200 OK {accepted: true}
```

## Use Case 2: Microservices Zero-Trust with Dapr

### Scenario
An e-commerce platform with 15 microservices. All service-to-service
communication is mTLS-encrypted. Access control enforced via SPIFFE identities.

```mermaid
flowchart TD
    subgraph External["External (Internet)"]
        WEB["🌐 Web App"]
        MOBILE["📱 Mobile App"]
    end

    subgraph K8s["Kubernetes Cluster"]
        subgraph Infra["Infrastructure"]
            CM["cert-manager<br/>Let's Encrypt certs"]
            SENTRY["Dapr Sentry<br/>Workload certs"]
            DNS["CoreDNS"]
        end

        ING["🚪 Ingress<br/>TLS: LE cert"]

        subgraph NS_Prod["namespace: production"]
            subgraph OrderPod["order-service"]
                ORDER["🌐 Order API"]
                ORDER_SC["🛡️ Dapr Sidecar<br/>SPIFFE: .../order-service"]
            end

            subgraph PayPod["payment-service"]
                PAY["💳 Payment"]
                PAY_SC["🛡️ Dapr Sidecar<br/>SPIFFE: .../payment-service"]
            end

            subgraph InvPod["inventory-service"]
                INV["📦 Inventory"]
                INV_SC["🛡️ Dapr Sidecar<br/>SPIFFE: .../inventory-service"]
            end

            subgraph NotifPod["notification-service"]
                NOTIF["📧 Notifications"]
                NOTIF_SC["🛡️ Dapr Sidecar<br/>SPIFFE: .../notification-service"]
            end
        end
    end

    WEB & MOBILE -->|"TLS"| ING
    ING -->|"HTTP"| ORDER

    ORDER_SC <-->|"🔒 mTLS"| PAY_SC
    ORDER_SC <-->|"🔒 mTLS"| INV_SC
    ORDER_SC <-->|"🔒 mTLS"| NOTIF_SC
    PAY_SC <-->|"🔒 mTLS"| NOTIF_SC

    CM -->|"LE cert"| ING
    CM -->|"Root CA"| SENTRY
    SENTRY -->|"Workload certs"| ORDER_SC & PAY_SC & INV_SC & NOTIF_SC

    style External fill:#fff3bf
    style Infra fill:#e7f5ff
    style NS_Prod fill:#d3f9d8
```

### Access Control Matrix

```mermaid
flowchart TD
    subgraph Policy["Dapr Access Control (defaultAction: deny)"]
        ORDER_P["order-service can call:"]
        ORDER_P --> PAY_ALLOW["✅ payment-service<br/>POST /process<br/>POST /refund"]
        ORDER_P --> INV_ALLOW["✅ inventory-service<br/>POST /reserve<br/>GET /stock"]
        ORDER_P --> NOTIF_ALLOW["✅ notification-service<br/>POST /send"]
        ORDER_P --> PAY_DENY["❌ payment-service<br/>GET /admin"]

        PAY_P["payment-service can call:"]
        PAY_P --> NOTIF_PAY["✅ notification-service<br/>POST /send"]
        PAY_P --> ORDER_DENY["❌ order-service<br/>(no callback needed)"]
        PAY_P --> INV_DENY["❌ inventory-service<br/>(no direct access)"]

        INV_P["inventory-service can call:"]
        INV_P --> NOTIF_INV["✅ notification-service<br/>POST /send<br/>(low stock alerts)"]
        INV_P --> OTHER_DENY["❌ Everything else"]
    end

    style PAY_ALLOW fill:#51cf66,color:#fff
    style INV_ALLOW fill:#51cf66,color:#fff
    style NOTIF_ALLOW fill:#51cf66,color:#fff
    style NOTIF_PAY fill:#51cf66,color:#fff
    style NOTIF_INV fill:#51cf66,color:#fff
    style PAY_DENY fill:#ff6b6b,color:#fff
    style ORDER_DENY fill:#ff6b6b,color:#fff
    style INV_DENY fill:#ff6b6b,color:#fff
    style OTHER_DENY fill:#ff6b6b,color:#fff
```

## Use Case 3: Certificate Rotation - Zero Downtime

### Scenario
A running service needs its certificate replaced without dropping any connections.

```mermaid
sequenceDiagram
    participant Client as 🖥️ Active Clients<br/>(existing connections)
    participant NewClient as 🖥️ New Clients
    participant Server as 🌐 Server
    participant Sentry as 🏛️ Dapr Sentry /<br/>cert-manager

    Note over Client,Sentry: Current: Cert A (issued 17h ago, expires in 7h)

    rect rgb(255, 245, 230)
        Note over Server,Sentry: Rotation triggered (70% of TTL)
        Server->>Server: 1. Generate NEW key pair
        Server->>Sentry: 2. New CSR
        Sentry-->>Server: 3. New signed cert (Cert B)

        Server->>Server: 4. ATOMIC SWAP<br/>Active cert: A → B
    end

    Note over Client,Server: 5. Existing connections (using Cert A)<br/>continue working until they close naturally

    Client->>Server: Request on existing connection<br/>(still using Cert A session keys)<br/>✅ Works fine

    Note over NewClient,Server: 6. New connections use Cert B

    NewClient->>Server: New TLS handshake<br/>(server presents Cert B)<br/>✅ New cert

    Note over Client,Sentry: 7h later: Cert A expires<br/>All old connections have closed by now<br/>Only Cert B in use

    Note over Client,Sentry: ✅ Zero dropped connections<br/>✅ Zero downtime
```

## Use Case 4: Multi-Environment Certificate Strategy

### Scenario
Separate certificate strategies for dev, staging, and production environments.

```mermaid
flowchart TD
    subgraph Dev["Development"]
        DEV_ISSUER["Self-Signed Issuer<br/>(no real CA needed)"]
        DEV_CERT["Self-signed certs<br/>Duration: 365 days<br/>Auto-generated"]
        DEV_NOTE["Quick setup<br/>No external deps<br/>Not for production!"]
        DEV_ISSUER --> DEV_CERT
    end

    subgraph Staging["Staging"]
        STG_ISSUER["ClusterIssuer<br/>Let's Encrypt STAGING<br/>(rate limit friendly)"]
        STG_CA["Internal CA Issuer<br/>(for service mTLS)"]
        STG_CERT["LE staging certs<br/>(not browser-trusted)<br/>+ Internal mTLS certs"]
        STG_ISSUER --> STG_CERT
        STG_CA --> STG_CERT
    end

    subgraph Production["Production"]
        PROD_LE["ClusterIssuer<br/>Let's Encrypt PRODUCTION<br/>(for Ingress)"]
        PROD_CA["Internal CA Issuer<br/>(for service mTLS)"]
        PROD_DAPR["Dapr Sentry<br/>(workload certs<br/>from cert-manager CA)"]
        PROD_CERTS["LE production certs<br/>+ Internal mTLS certs<br/>+ Dapr workload certs"]

        PROD_LE --> PROD_CERTS
        PROD_CA --> PROD_CERTS
        PROD_CA -->|"Root CA"| PROD_DAPR
        PROD_DAPR --> PROD_CERTS

        PROD_FEATURES["Features:<br/>✅ Auto-renewal<br/>✅ Short-lived certs (24h Dapr)<br/>✅ OCSP stapling<br/>✅ Certificate monitoring<br/>✅ Access control policies"]
    end

    style Dev fill:#fff3bf
    style Staging fill:#e7f5ff
    style Production fill:#d3f9d8
```

## Use Case 5: Complete Request Flow (External → Internal)

### Scenario
A mobile app creates an order. The request flows through TLS termination,
internal mTLS, and hits multiple services.

```mermaid
sequenceDiagram
    participant Mobile as 📱 Mobile App
    participant DNS as 🌐 External DNS<br/>(Route53)
    participant Ingress as 🚪 Ingress<br/>(nginx)
    participant CoreDNS as 📡 CoreDNS
    participant OrderSC as 🛡️ Order Sidecar
    participant Order as 🌐 Order Service
    participant PaySC as 🛡️ Payment Sidecar
    participant Pay as 💳 Payment Service

    Mobile->>DNS: 1. Resolve orders.api.example.com
    DNS-->>Mobile: 203.0.113.50 (Load Balancer IP)

    rect rgb(255, 245, 230)
        Note over Mobile,Ingress: External TLS (Let's Encrypt cert from cert-manager)
        Mobile->>Ingress: 2. TLS handshake<br/>Server cert: CN=orders.api.example.com<br/>Issued by: Let's Encrypt (R3)
        Mobile->>Ingress: 3. POST /orders<br/>{product: "widget", qty: 5}
    end

    rect rgb(230, 240, 255)
        Note over Ingress,Order: Internal HTTP (within cluster)
        Ingress->>Order: 4. Forward to order-service:80<br/>(plain HTTP, trusted network)
    end

    Order->>OrderSC: 5. dapr.InvokeMethodAsync<br/>("payment-service", "process", order)<br/>→ localhost:3500

    OrderSC->>CoreDNS: 6. Resolve payment-service
    CoreDNS-->>OrderSC: payment-service.production.svc.cluster.local<br/>→ 10.96.78.456

    rect rgb(255, 230, 230)
        Note over OrderSC,PaySC: Dapr mTLS (automatic workload certs)
        OrderSC->>PaySC: 7. mTLS handshake<br/>Order cert: spiffe://.../order-service<br/>Payment cert: spiffe://.../payment-service
        PaySC->>PaySC: 8. Verify SPIFFE ID ✅<br/>Check access policy ✅
    end

    PaySC->>Pay: 9. localhost:5000<br/>POST /process<br/>(plain HTTP)

    Pay-->>PaySC: 10. {success: true}
    PaySC-->>OrderSC: 11. Encrypted response
    OrderSC-->>Order: 12. HTTP response

    Order-->>Ingress: 13. {orderId: 42, status: "completed"}
    Ingress-->>Mobile: 14. TLS encrypted response

    Note over Mobile,Pay: 3 layers of certificate trust:<br/>① Let's Encrypt (external TLS)<br/>② Dapr Sentry (service mTLS)<br/>③ Kubernetes PKI (control plane)
```

## Use Case 6: Device Onboarding and Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Manufacturing: Device assembled

    Manufacturing --> Provisioned: Factory provisioning<br/>(key pair generated in TPM,<br/>CSR signed by device CA)

    Provisioned --> FirstConnect: Device shipped & powered on

    FirstConnect --> Active: mTLS handshake successful<br/>(cert validated, device registered)

    Active --> Active: Normal operation<br/>(sending telemetry via mTLS)

    Active --> CertRenewal: Certificate approaching expiry<br/>(renewBefore threshold)
    CertRenewal --> Active: New cert issued<br/>(auto-rotation)

    Active --> Suspended: Security event detected<br/>(anomalous behavior)
    Suspended --> Active: Investigation complete<br/>(cert reissued)
    Suspended --> Revoked: Confirmed compromise

    Active --> Revoked: Key compromise detected
    Revoked --> Decommissioned: Device recalled

    Active --> Decommissioned: End of life

    Decommissioned --> [*]: Cert added to CRL<br/>Device removed from registry

    note right of Active
        Certificate metadata used for:
        - Identity (CN)
        - Fleet routing (OU)
        - Access control (role)
        - Audit trail (serial, thumbprint)
    end note

    note right of CertRenewal
        Short-lived certs (24h-90d)
        reduce revocation need
    end note
```

## Use Case 7: Troubleshooting Decision Tree

```mermaid
flowchart TD
    PROBLEM["🔴 mTLS Connection Failed"]

    PROBLEM --> Q1{"Can client reach<br/>server at all?<br/>(ping/telnet port)"}
    Q1 -->|No| FIX1["Fix: Network/firewall<br/>Check K8s NetworkPolicy<br/>Check CoreDNS resolution"]

    Q1 -->|Yes| Q2{"TLS handshake<br/>succeeds?"}
    Q2 -->|No| Q3{"Error message?"}

    Q3 -->|"certificate signed by<br/>unknown authority"| FIX2["Fix: Trust store missing CA cert<br/>• Server: Check CustomTrustStore<br/>• Client: Check ServerCertValidation<br/>• Dapr: Check dapr-trust-bundle secret"]

    Q3 -->|"certificate has expired"| FIX3["Fix: Cert renewal failed<br/>• Check cert-manager logs<br/>• Check Dapr Sentry is running<br/>• Verify NTP clock sync"]

    Q3 -->|"bad certificate"| FIX4["Fix: Client cert rejected<br/>• Missing clientAuth EKU?<br/>• Wrong CA signed it?<br/>• Cert not sent? Check ClientCertificateMode"]

    Q3 -->|"hostname mismatch"| FIX5["Fix: SAN doesn't match<br/>• Check cert SAN vs requested hostname<br/>• Add all DNS names to cert<br/>• Check CoreDNS resolution"]

    Q2 -->|Yes| Q4{"HTTP 401<br/>Unauthorized?"}
    Q4 -->|Yes| FIX6["Fix: Auth middleware<br/>• Cert chain invalid (check CA in CustomTrustStore)<br/>• OnCertificateValidated failed<br/>• Check cert-manager cert status"]

    Q4 -->|No| Q5{"HTTP 403<br/>Forbidden?"}
    Q5 -->|Yes| FIX7["Fix: Authorization failed<br/>• Check OU → Role mapping<br/>• Check [Authorize] policy<br/>• Dapr: Check access control policy<br/>• Check SPIFFE ID matches policy"]

    Q5 -->|No| FIX8["✅ Connection works!<br/>Check application logic"]

    style PROBLEM fill:#ff6b6b,color:#fff
    style FIX1 fill:#4c6ef5,color:#fff
    style FIX2 fill:#4c6ef5,color:#fff
    style FIX3 fill:#4c6ef5,color:#fff
    style FIX4 fill:#4c6ef5,color:#fff
    style FIX5 fill:#4c6ef5,color:#fff
    style FIX6 fill:#4c6ef5,color:#fff
    style FIX7 fill:#4c6ef5,color:#fff
    style FIX8 fill:#51cf66,color:#fff
```
