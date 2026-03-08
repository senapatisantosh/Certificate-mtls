# 06 - Kubernetes cert-manager & CoreDNS - Diagrams

## 6.1 Certificates in Kubernetes - The Big Picture

```mermaid
flowchart TD
    subgraph External["External Traffic"]
        BROWSER["🌐 Browser / Client"]
    end

    subgraph Cluster["Kubernetes Cluster"]
        subgraph ControlPlane["Control Plane (built-in PKI)"]
            API["API Server"]
            ETCD["etcd"]
            KUBELET["Kubelet"]
            API <-->|"mTLS<br/>(K8s built-in PKI)"| ETCD
            API <-->|"mTLS<br/>(K8s built-in PKI)"| KUBELET
        end

        subgraph CertInfra["Certificate Infrastructure"]
            CM["📦 cert-manager<br/>Issues/renews certs"]
            COREDNS["📡 CoreDNS<br/>Internal DNS"]
            CM_SENTRY["🏛️ Dapr Sentry<br/>Workload certs"]
        end

        subgraph Workloads["Application Workloads"]
            INGRESS["🚪 Ingress Controller<br/>TLS: Let's Encrypt cert<br/>(from cert-manager)"]
            POD_A["📦 Pod A + Dapr Sidecar<br/>mTLS: Dapr workload cert"]
            POD_B["📦 Pod B + Dapr Sidecar<br/>mTLS: Dapr workload cert"]
        end
    end

    BROWSER <-->|"① TLS<br/>Let's Encrypt cert"| INGRESS
    INGRESS -->|"② HTTP<br/>(internal)"| POD_A
    POD_A <-->|"③ mTLS<br/>Dapr auto certs"| POD_B

    CM -->|"Issues"| INGRESS
    CM -->|"Root CA for"| CM_SENTRY
    CM_SENTRY -->|"Signs workload<br/>certs for"| POD_A
    CM_SENTRY -->|"Signs workload<br/>certs for"| POD_B
    COREDNS -->|"Resolves"| POD_A
    COREDNS -->|"Resolves"| POD_B

    style External fill:#fff3bf
    style ControlPlane fill:#ffe3e3
    style CertInfra fill:#e7f5ff
    style Workloads fill:#d3f9d8
```

## 6.2 cert-manager Architecture

```mermaid
flowchart TD
    subgraph CertManager["cert-manager (namespace: cert-manager)"]
        CTRL["📦 cert-manager<br/>Controller<br/>─────────<br/>Watches CRDs<br/>Manages lifecycle"]
        WEBHOOK["📦 cert-manager<br/>Webhook<br/>─────────<br/>Validates CRDs"]
        CAINJECTOR["📦 cert-manager<br/>CA Injector<br/>─────────<br/>Injects CA bundles<br/>into webhooks"]
    end

    subgraph CRDs["Custom Resources (your namespace)"]
        CLUSTERISSUER["ClusterIssuer<br/>(cluster-wide)"]
        ISSUER["Issuer<br/>(namespaced)"]
        CERTIFICATE["Certificate<br/>(desired state)"]
        CERTREQ["CertificateRequest<br/>(internal)"]
        ORDER["Order<br/>(ACME only)"]
        CHALLENGE["Challenge<br/>(ACME only)"]
    end

    subgraph External["External CAs"]
        LE["🏛️ Let's Encrypt<br/>ACME Server"]
        CUSTOM_CA["🏛️ Internal CA<br/>(self-signed)"]
    end

    subgraph Output["Output"]
        SECRET["🔐 Kubernetes Secret<br/>type: kubernetes.io/tls<br/>tls.crt: (cert chain)<br/>tls.key: (private key)<br/>ca.crt: (CA cert)"]
    end

    CTRL -->|Watches| CERTIFICATE
    CTRL -->|Creates| CERTREQ
    CERTREQ -->|For ACME| ORDER
    ORDER -->|Creates| CHALLENGE
    CHALLENGE -->|Validates with| LE

    CERTIFICATE -->|References| CLUSTERISSUER
    CERTIFICATE -->|References| ISSUER

    CLUSTERISSUER -->|"ACME type"| LE
    CLUSTERISSUER -->|"CA type"| CUSTOM_CA
    ISSUER -->|"ACME type"| LE

    CTRL -->|"Creates/Updates"| SECRET

    style CTRL fill:#4c6ef5,color:#fff
    style SECRET fill:#51cf66,color:#fff
    style LE fill:#e64980,color:#fff
```

## 6.3 Issuer vs ClusterIssuer

```mermaid
flowchart TD
    subgraph CI["ClusterIssuer (cluster-wide)"]
        CI_DEF["name: letsencrypt-prod<br/>No namespace<br/>─────────<br/>Can issue certs<br/>in ANY namespace"]
    end

    subgraph NS_A["Namespace: production"]
        I_A["Issuer<br/>name: internal-ca<br/>─────────<br/>Only issues certs<br/>in production"]
        CERT_A["Certificate<br/>issuerRef: internal-ca<br/>kind: Issuer ✅"]
        CERT_A2["Certificate<br/>issuerRef: letsencrypt-prod<br/>kind: ClusterIssuer ✅"]
    end

    subgraph NS_B["Namespace: staging"]
        I_B["Issuer<br/>name: staging-ca<br/>─────────<br/>Only issues certs<br/>in staging"]
        CERT_B["Certificate<br/>issuerRef: staging-ca<br/>kind: Issuer ✅"]
        CERT_B2["Certificate<br/>issuerRef: letsencrypt-prod<br/>kind: ClusterIssuer ✅"]
        CERT_B3["Certificate<br/>issuerRef: internal-ca<br/>kind: Issuer ❌<br/>WRONG namespace!"]
    end

    CI_DEF -->|"Can issue in"| NS_A
    CI_DEF -->|"Can issue in"| NS_B
    I_A -->|"Can only issue in"| NS_A
    I_B -->|"Can only issue in"| NS_B

    style CI fill:#4c6ef5,color:#fff
    style I_A fill:#be4bdb,color:#fff
    style I_B fill:#f59f00,color:#000
    style CERT_B3 fill:#ff6b6b,color:#fff
```

## 6.4 Certificate Lifecycle in cert-manager

```mermaid
sequenceDiagram
    participant User as 👤 You
    participant CM as 📦 cert-manager
    participant Issuer as 🏛️ ClusterIssuer
    participant LE as 🌐 Let's Encrypt
    participant K8s as ☸️ Kubernetes

    User->>K8s: 1. kubectl apply Certificate resource<br/>{domain: api.example.com, issuer: letsencrypt-prod}

    CM->>K8s: 2. Watches: Certificate created!
    CM->>CM: 3. Create CertificateRequest

    CM->>Issuer: 4. Send CSR to ClusterIssuer

    rect rgb(240, 255, 240)
        Note over Issuer,LE: ACME Flow (same as doc 01)
        Issuer->>LE: 5. New order for api.example.com
        LE-->>Issuer: 6. Challenges

        CM->>CM: 7. Create temp Pod+Service+Ingress<br/>(HTTP-01 challenge solver)

        LE->>CM: 8. Fetch challenge token
        CM-->>LE: 9. Return token ✅

        Issuer->>LE: 10. Submit CSR
        LE-->>Issuer: 11. Signed certificate chain
    end

    CM->>K8s: 12. Create/Update Secret<br/>name: api-example-com-tls<br/>type: kubernetes.io/tls<br/>tls.crt + tls.key + ca.crt

    CM->>CM: 13. Clean up temp challenge resources

    Note over CM,K8s: ⏰ Auto-renewal: renewBefore deadline

    CM->>CM: 14. Monitor cert expiry...<br/>Trigger renewal when<br/>renewBefore is reached

    CM->>Issuer: 15. Repeat steps 4-12<br/>(new cert, update Secret)

    Note over User,K8s: Pods mounting the Secret get the new cert<br/>(may need restart depending on app)
```

## 6.5 ACME HTTP-01 Challenge in Kubernetes

```mermaid
flowchart TD
    CM["cert-manager controller"]
    CM -->|"1. Creates"| SOLVER_POD["Temporary Pod<br/>Challenge solver<br/>Serves token at<br/>/.well-known/acme-challenge/"]
    CM -->|"2. Creates"| SOLVER_SVC["Temporary Service<br/>Routes to solver pod"]
    CM -->|"3. Creates"| SOLVER_ING["Temporary Ingress<br/>Routes external traffic<br/>to solver service"]

    LE["Let's Encrypt<br/>Validation Server"]
    LE -->|"4. HTTP GET<br/>http://api.example.com/<br/>.well-known/acme-challenge/{token}"| SOLVER_ING
    SOLVER_ING --> SOLVER_SVC
    SOLVER_SVC --> SOLVER_POD
    SOLVER_POD -->|"5. Returns<br/>key authorization"| LE

    LE -->|"6. Validated! ✅"| CM

    CM -->|"7. Cleanup"| CLEANUP["Delete temp:<br/>Pod, Service, Ingress"]

    style CM fill:#4c6ef5,color:#fff
    style SOLVER_POD fill:#f59f00,color:#000
    style SOLVER_SVC fill:#f59f00,color:#000
    style SOLVER_ING fill:#f59f00,color:#000
    style LE fill:#e64980,color:#fff
```

## 6.6 Internal CA Bootstrap with cert-manager

```mermaid
flowchart TD
    subgraph Step1["Step 1: Self-Signed ClusterIssuer"]
        SS["ClusterIssuer<br/>name: selfsigned-issuer<br/>type: selfSigned"]
    end

    subgraph Step2["Step 2: Root CA Certificate"]
        ROOT_CERT["Certificate<br/>name: internal-root-ca<br/>isCA: true<br/>duration: 10 years<br/>issuerRef: selfsigned-issuer"]
        ROOT_SECRET["Secret<br/>internal-root-ca-secret<br/>tls.crt + tls.key"]
    end

    subgraph Step3["Step 3: CA ClusterIssuer"]
        CA_ISSUER["ClusterIssuer<br/>name: internal-ca-issuer<br/>type: ca<br/>secretName: internal-root-ca-secret"]
    end

    subgraph Step4["Step 4: Workload Certificates"]
        W1["Certificate<br/>order-service-mtls<br/>issuerRef: internal-ca-issuer"]
        W2["Certificate<br/>payment-service-mtls<br/>issuerRef: internal-ca-issuer"]
        W1_SEC["Secret: order-service-mtls-tls"]
        W2_SEC["Secret: payment-service-mtls-tls"]
    end

    SS -->|"Signs"| ROOT_CERT
    ROOT_CERT -->|"Stored in"| ROOT_SECRET
    ROOT_SECRET -->|"Used by"| CA_ISSUER
    CA_ISSUER -->|"Signs"| W1
    CA_ISSUER -->|"Signs"| W2
    W1 -->|"Creates"| W1_SEC
    W2 -->|"Creates"| W2_SEC

    style SS fill:#f59f00,color:#000
    style ROOT_CERT fill:#e64980,color:#fff
    style CA_ISSUER fill:#be4bdb,color:#fff
    style W1 fill:#4c6ef5,color:#fff
    style W2 fill:#4c6ef5,color:#fff
```

## 6.7 CoreDNS Architecture

```mermaid
flowchart TD
    subgraph CoreDNS_System["CoreDNS (kube-system namespace)"]
        COREDNS["📡 CoreDNS Pods<br/>Listen: UDP/TCP 53<br/>ClusterIP: 10.96.0.10<br/>─────────<br/>Watches K8s API<br/>for Services & Endpoints"]
    end

    subgraph Pods["Application Pods"]
        POD_A["Pod A<br/>/etc/resolv.conf:<br/>nameserver 10.96.0.10<br/>search default.svc.cluster.local<br/>ndots: 5"]
        POD_B["Pod B"]
    end

    subgraph Services["Kubernetes Services"]
        SVC1["Service: order-service<br/>ClusterIP: 10.96.45.123<br/>Namespace: production"]
        SVC2["Service: payment-service<br/>ClusterIP: 10.96.78.456<br/>Namespace: production"]
    end

    POD_A -->|"DNS query:<br/>order-service.production<br/>.svc.cluster.local"| COREDNS
    COREDNS -->|"Response:<br/>10.96.45.123"| POD_A

    COREDNS -->|"Watches"| SVC1
    COREDNS -->|"Watches"| SVC2

    subgraph DNSRecords["DNS Records Created"]
        R1["A: order-service.production.svc.cluster.local<br/>→ 10.96.45.123"]
        R2["A: payment-service.production.svc.cluster.local<br/>→ 10.96.78.456"]
        R3["SRV: _http._tcp.order-service.production.svc...<br/>→ 0 100 80 order-service..."]
    end

    style COREDNS fill:#4c6ef5,color:#fff
    style DNSRecords fill:#d3f9d8
```

## 6.8 DNS Name Resolution and Search Domains

```mermaid
flowchart TD
    QUERY["Pod in 'default' namespace<br/>queries: 'order-service'"]

    QUERY --> S1{"1. order-service<br/>.default.svc.cluster.local"}
    S1 -->|"Not found"| S2{"2. order-service<br/>.svc.cluster.local"}
    S2 -->|"Not found"| S3{"3. order-service<br/>.cluster.local"}
    S3 -->|"Not found"| S4{"4. order-service.<br/>(forward to upstream DNS)"}

    S1 -->|"Found!"| RESULT1["✅ Same namespace service"]

    QUERY2["Pod queries:<br/>'order-service.production'"]
    QUERY2 --> S2A{"1. order-service.production<br/>.default.svc.cluster.local"}
    S2A -->|"Not found"| S2B{"2. order-service.production<br/>.svc.cluster.local"}
    S2B -->|"Found!"| RESULT2["✅ Cross-namespace service"]

    QUERY3["Pod queries FQDN:<br/>'order-service.production<br/>.svc.cluster.local'"]
    QUERY3 --> DIRECT["Direct resolution<br/>(no search path)"]
    DIRECT -->|"Found!"| RESULT3["✅ Exact match"]

    style RESULT1 fill:#51cf66,color:#fff
    style RESULT2 fill:#51cf66,color:#fff
    style RESULT3 fill:#51cf66,color:#fff
```

## 6.9 DNS ↔ Certificate SAN Relationship

```mermaid
flowchart TD
    subgraph CertSANs["Certificate SANs"]
        SAN["Certificate for order-service:<br/>SAN DNS names:<br/>• order-service<br/>• order-service.production<br/>• order-service.production.svc<br/>• order-service.production.svc.cluster.local"]
    end

    subgraph DNSResolves["CoreDNS Resolves"]
        DNS["order-service.production.svc.cluster.local<br/>→ 10.96.45.123 (ClusterIP)"]
    end

    subgraph TLSCheck["TLS Hostname Verification"]
        CLIENT["Client connects to:<br/>order-service.production.svc.cluster.local"]
        SERVER["Server presents cert with<br/>SAN: DNS:order-service.production.svc.cluster.local"]
        MATCH{"SAN matches<br/>requested hostname?"}
        MATCH -->|"Yes ✅"| SUCCESS["TLS handshake succeeds"]
        MATCH -->|"No ❌"| FAIL["TLS handshake fails:<br/>hostname mismatch"]
    end

    CLIENT --> DNS
    DNS --> SERVER
    SERVER --> MATCH

    style SAN fill:#4c6ef5,color:#fff
    style DNS fill:#be4bdb,color:#fff
    style SUCCESS fill:#51cf66,color:#fff
    style FAIL fill:#ff6b6b,color:#fff
```

## 6.10 cert-manager + Dapr Integration

```mermaid
flowchart TD
    subgraph CertManager["cert-manager"]
        SS_ISSUER["Self-Signed<br/>ClusterIssuer"]
        DAPR_CA_CERT["Certificate:<br/>dapr-root-ca<br/>isCA: true<br/>O=dapr.io<br/>CN=cluster.local"]
        DAPR_SECRET["Secret:<br/>dapr-trust-bundle<br/>tls.crt + tls.key"]

        SS_ISSUER -->|Signs| DAPR_CA_CERT
        DAPR_CA_CERT -->|Creates| DAPR_SECRET
    end

    subgraph DaprSystem["Dapr Control Plane"]
        SENTRY["Dapr Sentry<br/>Reads root CA from<br/>dapr-trust-bundle Secret"]
    end

    subgraph Workloads["Application Pods"]
        W1["Sidecar 1<br/>Workload cert signed by Sentry<br/>(which uses cert-manager's root)"]
        W2["Sidecar 2<br/>Workload cert signed by Sentry"]
    end

    DAPR_SECRET -->|"Root CA"| SENTRY
    SENTRY -->|"Signs<br/>workload certs"| W1
    SENTRY -->|"Signs<br/>workload certs"| W2
    W1 <-->|"🔒 mTLS"| W2

    subgraph Benefits["Benefits"]
        B1["cert-manager handles<br/>root CA rotation"]
        B2["Centralized cert<br/>management"]
        B3["Same CA for Dapr<br/>and non-Dapr services"]
    end

    style CertManager fill:#e7f5ff
    style DaprSystem fill:#fff3bf
    style Workloads fill:#d3f9d8
    style Benefits fill:#f3f0ff
```
