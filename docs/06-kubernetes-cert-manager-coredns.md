# 06 - Kubernetes cert-manager, ClusterIssuer, and CoreDNS

## Table of Contents
- [The Big Picture: Certificates in Kubernetes](#the-big-picture-certificates-in-kubernetes)
- [cert-manager: What It Is and How It Works](#cert-manager-what-it-is-and-how-it-works)
- [Issuer vs ClusterIssuer](#issuer-vs-clusterissuer)
- [Certificate Resources](#certificate-resources)
- [ACME / Let's Encrypt with cert-manager](#acme--lets-encrypt-with-cert-manager)
- [Self-Signed and Internal CA Issuers](#self-signed-and-internal-ca-issuers)
- [cert-manager + Dapr Integration](#cert-manager--dapr-integration)
- [CoreDNS: How Kubernetes DNS Works](#coredns-how-kubernetes-dns-works)
- [How DNS and Certificates Interact](#how-dns-and-certificates-interact)
- [Complete Architecture: Everything Together](#complete-architecture-everything-together)
- [Troubleshooting Guide](#troubleshooting-guide)

---

## The Big Picture: Certificates in Kubernetes

In a Kubernetes cluster, certificates are used everywhere:

```
+---------------------------------------------------------------------+
|                        Kubernetes Cluster                           |
|                                                                     |
|  1. API Server <---> Kubelet           (mTLS - built-in PKI)       |
|  2. API Server <---> etcd              (mTLS - built-in PKI)       |
|  3. Ingress <---> External Clients     (TLS  - cert-manager)       |
|  4. Pod <---> Pod (via Service Mesh)   (mTLS - Dapr/Istio/Linkerd) |
|  5. Pod <---> External Service         (TLS  - custom certs)       |
|                                                                     |
|  Kubernetes has its OWN PKI for cluster components (#1, #2)         |
|  cert-manager manages certs for YOUR workloads (#3, #4, #5)        |
+---------------------------------------------------------------------+
```

### Kubernetes Built-in PKI (for reference)

```
  /etc/kubernetes/pki/          (on control plane nodes)
  ├── ca.crt                    Kubernetes CA (root of cluster trust)
  ├── ca.key                    Kubernetes CA private key
  ├── apiserver.crt             API server certificate
  ├── apiserver.key             API server private key
  ├── apiserver-kubelet-client.crt   API server -> Kubelet mTLS
  ├── apiserver-kubelet-client.key
  ├── front-proxy-ca.crt        Front proxy CA
  ├── front-proxy-client.crt    Front proxy client cert
  ├── etcd/
  │   ├── ca.crt                etcd CA
  │   ├── server.crt            etcd server cert
  │   ├── peer.crt              etcd peer mTLS cert
  │   └── ...
  └── sa.key / sa.pub           ServiceAccount token signing key pair

  These are SEPARATE from your application certs.
  You almost never touch these directly.
```

---

## cert-manager: What It Is and How It Works

**cert-manager** is a Kubernetes-native certificate management controller.
It automates the issuance and renewal of TLS certificates.

### Architecture

```
+---------------------------------------------------------------------+
|                        Kubernetes Cluster                           |
|                                                                     |
|  +---------------------+     +--------------------------+          |
|  | cert-manager        |     | cert-manager-webhook     |          |
|  | controller          |     | (validates CRDs)         |          |
|  | (runs in            |     |                          |          |
|  |  cert-manager ns)   |     +--------------------------+          |
|  |                     |                                           |
|  | Watches:            |     +--------------------------+          |
|  | - Certificate CRDs  |     | cert-manager-cainjector  |          |
|  | - Issuer CRDs       |     | (injects CA bundles into |          |
|  | - ClusterIssuer CRDs|     |  webhooks/API services)  |          |
|  | - CertificateRequest|     +--------------------------+          |
|  | - Order (ACME)      |                                           |
|  | - Challenge (ACME)  |                                           |
|  +----------|-----------+                                           |
|             |                                                       |
|             v                                                       |
|  +----------|-----------+                                           |
|  | Creates/manages:     |                                           |
|  | - Kubernetes Secrets |  <-- TLS certs stored as Secrets          |
|  |   (type: tls)        |      with tls.crt and tls.key            |
|  +----------------------+                                           |
+---------------------------------------------------------------------+
          |
          | (for ACME/Let's Encrypt)
          v
+-------------------+
| Let's Encrypt     |
| ACME Server       |
| (external)        |
+-------------------+
```

### Installation

```bash
# Install cert-manager using Helm
helm repo add jetstack https://charts.jetstack.io
helm repo update

helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true

# Verify
kubectl get pods -n cert-manager
# cert-manager-xxxx                 1/1  Running
# cert-manager-cainjector-xxxx      1/1  Running
# cert-manager-webhook-xxxx         1/1  Running
```

### Custom Resource Definitions (CRDs)

cert-manager adds these Kubernetes resource types:

```
+---------------------+---------------------------------------------------+
| CRD                 | Purpose                                           |
+---------------------+---------------------------------------------------+
| Issuer              | Namespaced certificate issuer (CA, ACME, etc.)    |
| ClusterIssuer       | Cluster-wide certificate issuer                   |
| Certificate         | Declares a desired certificate                    |
| CertificateRequest  | Internal: CSR sent to issuer                      |
| Order               | Internal: ACME order tracking                     |
| Challenge            | Internal: ACME challenge tracking                 |
+---------------------+---------------------------------------------------+
```

---

## Issuer vs ClusterIssuer

### Issuer (Namespaced)

```yaml
# Can only issue certs in the SAME namespace
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: letsencrypt-staging
  namespace: production           # <-- Only works in "production" namespace
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-staging-account-key
    solvers:
      - http01:
          ingress:
            class: nginx
```

### ClusterIssuer (Cluster-Wide)

```yaml
# Can issue certs in ANY namespace
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod          # No namespace - it's cluster-wide
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      # HTTP-01 solver (for standard web services)
      - http01:
          ingress:
            class: nginx

      # DNS-01 solver (for wildcards, non-web services)
      - dns01:
          cloudDNS:                     # Or route53, azureDNS, cloudflare
            project: my-gcp-project
            serviceAccountSecretRef:
              name: clouddns-dns01-solver-svc-acct
              key: key.json
```

### When to Use Which

```
+-------------------------+---------------------------+---------------------------+
| Scenario                | Use Issuer                | Use ClusterIssuer         |
+-------------------------+---------------------------+---------------------------+
| Team-specific CA        | Yes (each team has own)   | No                        |
| Shared Let's Encrypt    | No                        | Yes (one for all)         |
| Multi-tenant cluster    | Yes (isolation)           | Maybe (with RBAC)         |
| Simple single-team      | Either works              | Simpler to manage         |
| Internal CA per env     | Yes (dev/staging/prod)    | No                        |
+-------------------------+---------------------------+---------------------------+
```

---

## Certificate Resources

A `Certificate` resource tells cert-manager what certificate you want:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-example-com
  namespace: production
spec:
  # What to name the Kubernetes Secret that will hold the cert
  secretName: api-example-com-tls

  # Certificate details
  commonName: api.example.com       # CN field
  dnsNames:                          # SAN DNS names
    - api.example.com
    - api-internal.example.com
  ipAddresses:                       # SAN IPs (optional)
    - 10.0.1.100
  uris:                              # SAN URIs (for SPIFFE)
    - "spiffe://cluster.local/ns/production/sa/api-service"

  # Certificate properties
  duration: 2160h                    # 90 days
  renewBefore: 720h                  # Renew 30 days before expiry
  isCA: false
  privateKey:
    algorithm: ECDSA
    size: 256                        # P-256
    rotationPolicy: Always           # Generate new key on renewal

  # Key usages
  usages:
    - server auth
    - client auth                    # Include for mTLS!
    - digital signature
    - key encipherment

  # Subject fields (optional)
  subject:
    organizations:
      - "Acme Corp"
    organizationalUnits:
      - "Backend Services"

  # Which issuer to use
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer              # or Issuer
    group: cert-manager.io
```

### Certificate Lifecycle in cert-manager

```
  Certificate resource created
         |
         v
  cert-manager reads spec
         |
         v
  Creates CertificateRequest
         |
         v
  Sends CSR to Issuer/ClusterIssuer
         |
         +--> ACME Issuer:
         |    1. Creates Order
         |    2. Creates Challenge (HTTP-01 or DNS-01)
         |    3. Waits for validation
         |    4. Retrieves signed cert
         |
         +--> CA Issuer:
         |    1. Signs directly with CA cert/key
         |    2. Returns signed cert immediately
         |
         +--> Self-Signed Issuer:
              1. Signs with the generated key itself
              2. Returns self-signed cert
         |
         v
  cert-manager creates/updates Kubernetes Secret
         |
         v
  Secret contains:
    tls.crt:  PEM-encoded certificate + chain
    tls.key:  PEM-encoded private key
    ca.crt:   PEM-encoded CA certificate (optional)
         |
         v
  Your pods mount this Secret
  (or Ingress references it)
         |
         v
  [renewBefore deadline] --> cert-manager auto-renews
                             Updates the Secret
                             Pods pick up new cert
```

### The Resulting Kubernetes Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: api-example-com-tls
  namespace: production
  annotations:
    cert-manager.io/certificate-name: api-example-com
    cert-manager.io/issuer-name: letsencrypt-prod
    cert-manager.io/issuer-kind: ClusterIssuer
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJ...    # Base64-encoded PEM cert chain
  tls.key: LS0tLS1CRUdJ...    # Base64-encoded PEM private key
  ca.crt:  LS0tLS1CRUdJ...    # Base64-encoded CA cert (if available)
```

### Using the Certificate in a Pod

```yaml
# Mount as volume
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: myapp
          volumeMounts:
            - name: tls-certs
              mountPath: /etc/tls
              readOnly: true
      volumes:
        - name: tls-certs
          secret:
            secretName: api-example-com-tls

# In your .NET app:
# var cert = X509Certificate2.CreateFromPemFile(
#     "/etc/tls/tls.crt",
#     "/etc/tls/tls.key"
# );
```

### Using with Ingress (Automatic)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  annotations:
    # cert-manager will automatically create a Certificate resource!
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: api-example-com-tls    # cert-manager creates this
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-service
                port:
                  number: 80
```

---

## ACME / Let's Encrypt with cert-manager

### HTTP-01 Challenge Flow in Kubernetes

```
  cert-manager                    ACME Server              Let's Encrypt
  ============                    (Let's Encrypt)          Validation
                                                           Servers
  1. Create Order for
     api.example.com --------->   2. Return challenges

  3. Create temporary
     Pod + Service + Ingress
     to serve challenge token
     at:
     http://api.example.com/
     .well-known/acme-challenge/
     <token>

  4. Tell ACME "ready" -------->  5. Fetch challenge
                                     URL from multiple
                                     vantage points -----> 6. Hits your
                                                              Ingress ->
                                                              challenge Pod
                                                              returns token
                                  7. Validated!

  8. Submit CSR ------------->    9. Sign certificate

  10. Store in Secret <---------  11. Return cert chain

  12. Clean up temporary
      Pod/Service/Ingress
```

### DNS-01 Challenge Flow

```
  cert-manager                    DNS Provider             Let's Encrypt
  ============                    (CloudDNS/Route53)

  1. Create Order for
     *.example.com ------------>  2. Return challenges

  3. Create TXT record
     via DNS provider API:
     _acme-challenge.example.com
     = "token-value"  ----------> 4. TXT record created

  5. Tell ACME "ready" -------->  6. Query DNS for
                                     _acme-challenge.
                                     example.com TXT
                                     record

                                  7. Verified! Token matches.

  8. Submit CSR ------------->    9. Sign wildcard cert

  10. Store in Secret <--------   11. Return cert chain

  12. Delete TXT record -------> 13. Record removed
```

### Supported DNS Providers

```
Built-in solvers:
  - ACME DNS
  - Akamai
  - Azure DNS
  - CloudDNS (Google)
  - Cloudflare
  - DigitalOcean
  - RFC2136 (dynamic DNS update)
  - Route53 (AWS)

Webhook solvers (community):
  - GoDaddy, Namecheap, OVH, Hetzner, and many more
```

---

## Self-Signed and Internal CA Issuers

For internal services and mTLS, you often don't need Let's Encrypt.
Use an internal CA instead.

### Self-Signed Issuer (Bootstrap Only)

```yaml
# Step 1: Create a self-signed issuer (to bootstrap the CA)
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
```

### CA Issuer (Recommended for Internal mTLS)

```yaml
# Step 2: Create a root CA certificate using the self-signed issuer
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: internal-root-ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: "Internal Root CA"
  subject:
    organizations:
      - "Acme Corp"
  secretName: internal-root-ca-secret
  privateKey:
    algorithm: ECDSA
    size: 256
  duration: 87600h              # 10 years
  renewBefore: 8760h            # 1 year before expiry
  issuerRef:
    name: selfsigned-issuer
    kind: ClusterIssuer
    group: cert-manager.io

---
# Step 3: Create a ClusterIssuer that uses the root CA
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: internal-ca-issuer
spec:
  ca:
    secretName: internal-root-ca-secret   # References the CA cert/key Secret
```

### Issue Workload Certificates from Internal CA

```yaml
# Now issue certs for your services
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: order-service-mtls
  namespace: production
spec:
  secretName: order-service-mtls-tls
  commonName: order-service
  dnsNames:
    - order-service
    - order-service.production
    - order-service.production.svc
    - order-service.production.svc.cluster.local
  uris:
    - "spiffe://cluster.local/ns/production/sa/order-service"
  duration: 720h                # 30 days
  renewBefore: 240h             # Renew 10 days before expiry
  usages:
    - server auth
    - client auth               # For mTLS
    - digital signature
    - key encipherment
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always
  issuerRef:
    name: internal-ca-issuer
    kind: ClusterIssuer
```

### Trust Distribution

```yaml
# Distribute the CA cert so other services can trust it
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: internal-ca-bundle
spec:
  sources:
    - secret:
        name: "internal-root-ca-secret"
        key: "ca.crt"
  target:
    configMap:
      key: "ca-certificates.crt"
    namespaceSelector:
      matchLabels:
        trust-bundle: "internal"       # Only namespaces with this label

# Pods mount the ConfigMap to get the CA cert for verification
```

---

## cert-manager + Dapr Integration

You can use cert-manager to provide Dapr's root certificate:

```
  cert-manager                         Dapr Sentry
  ============                         ===========

  1. cert-manager issues
     a root CA cert ------+
     (internal-ca-issuer) |
                          v
  2. Stores in Kubernetes
     Secret:
     dapr-trust-bundle    -----------> 3. Sentry reads root
                                          cert from Secret

                                       4. Sentry uses it to
                                          sign workload certs
                                          for sidecars

  Benefits:
  - cert-manager handles root cert rotation
  - Centralized certificate management
  - Same CA can issue certs for Dapr AND non-Dapr services
```

### Configuration

```yaml
# cert-manager Certificate for Dapr's root CA
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: dapr-root-ca
  namespace: dapr-system
spec:
  isCA: true
  commonName: "cluster.local"
  subject:
    organizations:
      - "dapr.io"
  secretName: dapr-trust-bundle        # Dapr looks for this Secret name
  privateKey:
    algorithm: ECDSA
    size: 256
  duration: 8760h                       # 1 year
  renewBefore: 2160h                    # Renew 90 days before
  issuerRef:
    name: selfsigned-issuer
    kind: ClusterIssuer
```

```yaml
# Dapr Helm values to use cert-manager certs
global:
  mtls:
    enabled: true
    controlPlaneTrustDomain: "cluster.local"
dapr_sentry:
  tls:
    root:
      certPEM: ""                       # Empty - will use the Secret
    issuer:
      certPEM: ""
      keyPEM: ""
  # Tell Sentry to read from the cert-manager-managed Secret
  certificate:
    secretName: dapr-trust-bundle
```

---

## CoreDNS: How Kubernetes DNS Works

CoreDNS is the **DNS server** that runs inside every Kubernetes cluster.
It resolves service names to IP addresses.

### CoreDNS Architecture

```
+---------------------------------------------------------------------+
|                        Kubernetes Cluster                           |
|                                                                     |
|  CoreDNS (runs as a Deployment in kube-system namespace)           |
|  +-----------------------+                                          |
|  | CoreDNS Pod           |                                          |
|  | Listens on:           |                                          |
|  |   UDP/TCP 53          |                                          |
|  |   (cluster IP:        |                                          |
|  |    10.96.0.10)        |                                          |
|  |                       |                                          |
|  | Watches:              |                                          |
|  |   Kubernetes API      |                                          |
|  |   for Services &      |                                          |
|  |   Endpoints           |                                          |
|  +-----------|-----------+                                          |
|              |                                                       |
|    Resolves DNS queries from all pods                               |
|              |                                                       |
|  +-----------v-----------+         +------------------------+       |
|  | Pod A                 |         | Pod B                  |       |
|  | /etc/resolv.conf:     |         | /etc/resolv.conf:      |       |
|  |   nameserver 10.96.0.10|        |   nameserver 10.96.0.10|      |
|  |   search default.svc  |         |   search prod.svc      |      |
|  |    .cluster.local     |         |    .cluster.local      |       |
|  |   ndots: 5            |         |   ndots: 5             |       |
|  +------------------------+         +------------------------+       |
+---------------------------------------------------------------------+
```

### DNS Record Types Created by CoreDNS

```
Service: order-service in namespace "production"
==================================================

A Record (ClusterIP Service):
  order-service.production.svc.cluster.local  -->  10.96.45.123
                                                   (ClusterIP)

SRV Record:
  _http._tcp.order-service.production.svc.cluster.local
  -->  0 100 80 order-service.production.svc.cluster.local

Headless Service (ClusterIP: None):
  order-service.production.svc.cluster.local
  -->  10.244.1.5    (Pod IP 1)
       10.244.2.8    (Pod IP 2)
       10.244.3.12   (Pod IP 3)

Pod DNS:
  10-244-1-5.production.pod.cluster.local  -->  10.244.1.5
```

### DNS Search Domains and Resolution

```
From a pod in the "default" namespace:
======================================

Short name:    order-service
Search order:
  1. order-service.default.svc.cluster.local    (same namespace)
  2. order-service.svc.cluster.local            (any namespace? no - invalid)
  3. order-service.cluster.local                (cluster-level)
  4. order-service.                             (absolute - forward to upstream)

FQDN:          order-service.production.svc.cluster.local
  Resolves directly (no search path needed)

Cross-namespace: You must specify the namespace!
  order-service.production    (short form, uses search domain)
  order-service.production.svc.cluster.local  (FQDN)
```

### CoreDNS Configuration (Corefile)

```
# kubectl get configmap coredns -n kube-system -o yaml

apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors                          # Log errors
        health {                        # Health check endpoint
           lameduck 5s
        }
        ready                           # Readiness probe
        kubernetes cluster.local in-addr.arpa ip6.arpa {  # Kubernetes plugin
           pods insecure                # Pod DNS records
           fallthrough in-addr.arpa ip6.arpa
           ttl 30                       # DNS record TTL
        }
        prometheus :9153                # Metrics
        forward . /etc/resolv.conf {    # Forward external queries upstream
           max_concurrent 1000
        }
        cache 30                        # Cache DNS responses for 30 seconds
        loop                            # Detect forwarding loops
        reload                          # Reload config on change
        loadbalance                     # Round-robin DNS responses
    }
```

---

## How DNS and Certificates Interact

This is where it all comes together. DNS names in certificates must match
what DNS resolves to.

### The Connection

```
  cert-manager creates a cert with:
    dnsNames:
      - order-service.production.svc.cluster.local

  CoreDNS resolves:
    order-service.production.svc.cluster.local  -->  10.96.45.123

  When a client connects:
  1. Client resolves "order-service.production.svc.cluster.local"
     via CoreDNS -> gets 10.96.45.123

  2. Client connects to 10.96.45.123:443 (TLS)

  3. Server presents certificate with SAN:
     DNS:order-service.production.svc.cluster.local

  4. Client checks: does the SAN match the hostname I connected to?
     "order-service.production.svc.cluster.local" == SAN DNS name?
     YES -> TLS handshake succeeds

  If the cert had the WRONG DNS name:
     SAN: DNS:wrong-service.production.svc.cluster.local
     Client checks: "order-service.production..." != "wrong-service.production..."
     FAIL -> TLS handshake fails with "hostname mismatch"
```

### Why Multiple DNS Names in Certificates

```yaml
# You need SANs for ALL the ways a service can be addressed
dnsNames:
  - order-service                                      # Short name (same namespace)
  - order-service.production                            # With namespace
  - order-service.production.svc                        # With svc
  - order-service.production.svc.cluster.local          # FQDN
  - order-service.production.svc.cluster.local          # For cross-cluster
```

### DNS-01 Challenge and CoreDNS

```
For Let's Encrypt DNS-01 challenges:

  cert-manager needs to create TXT records in EXTERNAL DNS
  (not CoreDNS - CoreDNS is internal to the cluster)

  External DNS (Route53, CloudDNS, etc.):
    _acme-challenge.api.example.com  TXT  "challenge-token"

  Let's Encrypt validates against EXTERNAL DNS

  CoreDNS is NOT involved in ACME challenges
  CoreDNS only resolves INTERNAL cluster DNS names

  The flow:
  1. cert-manager creates TXT record in Route53/CloudDNS
  2. Let's Encrypt verifies via public DNS
  3. cert-manager stores cert in Kubernetes Secret
  4. Ingress controller loads cert from Secret
  5. CoreDNS resolves internal service names to Service ClusterIPs
  6. External DNS (separate from CoreDNS) maps external domains to Ingress IP
```

### ExternalDNS (Bonus: Connecting Internal and External DNS)

```
  ExternalDNS controller (optional add-on):
  ==========================================

  Watches Kubernetes Ingress/Service resources
  Creates DNS records in external DNS providers

  Example:
  - Ingress for api.example.com exists in cluster
  - ExternalDNS creates A record in Route53:
    api.example.com -> 203.0.113.50 (Ingress LoadBalancer IP)

  This is separate from CoreDNS but complements it:
  - CoreDNS: internal cluster DNS (pods resolving service names)
  - ExternalDNS: external DNS (internet resolving to your cluster)
```

---

## Complete Architecture: Everything Together

```
                    INTERNET
                       |
                       v
              +--------+--------+
              | External DNS    |
              | (Route53)       |
              | api.example.com |
              | -> 203.0.113.50 |
              +--------+--------+
                       |
                       v
+----------------------------------------------------------------------+
|                  KUBERNETES CLUSTER                                   |
|                                                                       |
|  +-----------------+     +------------------+                        |
|  | cert-manager    |     | CoreDNS          |                        |
|  |                 |     | (kube-system)    |                        |
|  | Manages:        |     |                  |                        |
|  | - TLS certs     |     | Resolves:        |                        |
|  | - ACME/LE       |     | *.svc.cluster    |                        |
|  | - Internal CA   |     |  .local          |                        |
|  +--------+--------+     +--------+---------+                        |
|           |                       |                                   |
|           v                       v                                   |
|  +--------+--------+     +-------+--------+                          |
|  | Kubernetes       |     | Service:       |                          |
|  | Secret:          |     | order-service  |                          |
|  | api-tls          |     | ClusterIP:     |                          |
|  | (tls.crt,        |     | 10.96.45.123   |                          |
|  |  tls.key)        |     +-------+--------+                          |
|  +--------+---------+             |                                   |
|           |                       |                                   |
|           v                       v                                   |
|  +--------+---------+    +--------+---------+     +-----------+      |
|  | Ingress          |    | Pod (app)        |     | Dapr      |      |
|  | Controller       |    |                  |     | Sentry    |      |
|  | (nginx/traefik)  |    | +---+  +------+  |     |           |      |
|  |                  |    | |App|  |Dapr  |  |     | Signs     |      |
|  | Uses cert from   |    | |.NET| |Sidecar| |     | workload  |      |
|  | Secret for TLS   |    | |   | |      |  |     | certs     |      |
|  | termination      |    | +---+  +------+  |     |           |      |
|  +------------------+    +------------------+     | Uses root |      |
|                                                    | CA from   |      |
|  External traffic:                                 | cert-mgr  |      |
|  Browser -> Ingress (TLS from Let's Encrypt cert) +-----------+      |
|                                                                       |
|  Internal traffic:                                                    |
|  Pod A sidecar -> Pod B sidecar (mTLS from Dapr/cert-manager)       |
|                                                                       |
|  DNS resolution:                                                      |
|  Pod queries CoreDNS -> resolves to Service ClusterIP -> routes to Pod|
+----------------------------------------------------------------------+
```

---

## Troubleshooting Guide

### cert-manager Issues

```bash
# Check Certificate status
kubectl get certificate -A
# NAME              READY   SECRET                AGE
# api-example-com   True    api-example-com-tls   5d

# If READY is False, check details:
kubectl describe certificate api-example-com -n production

# Check CertificateRequest
kubectl get certificaterequest -A
kubectl describe certificaterequest <name> -n <namespace>

# Check ACME Order (if using Let's Encrypt)
kubectl get order -A
kubectl describe order <name>

# Check ACME Challenge
kubectl get challenge -A
kubectl describe challenge <name>

# Check cert-manager logs
kubectl logs -l app=cert-manager -n cert-manager

# Common issues:
# 1. "challenge propagation check failed" -> DNS not propagated yet
# 2. "certificate does not match" -> Wrong DNS names in cert spec
# 3. "account registration failed" -> Email/ACME server URL wrong
# 4. "secret not found" -> CA secret missing for CA issuer
```

### CoreDNS Issues

```bash
# Check CoreDNS is running
kubectl get pods -n kube-system -l k8s-app=kube-dns

# Check CoreDNS logs
kubectl logs -l k8s-app=kube-dns -n kube-system

# Test DNS resolution from a pod
kubectl run dns-test --image=busybox:1.36 --rm -it -- nslookup order-service.production.svc.cluster.local
# Expected: Address: 10.96.45.123

# Test with dig (more detail)
kubectl run dns-test --image=tutum/dnsutils --rm -it -- dig order-service.production.svc.cluster.local

# Check CoreDNS config
kubectl get configmap coredns -n kube-system -o yaml

# Common issues:
# 1. "NXDOMAIN" -> Service doesn't exist or wrong namespace
# 2. "connection timed out" -> CoreDNS pod not running or network policy blocking
# 3. "SERVFAIL" -> CoreDNS misconfigured or upstream DNS failing
# 4. Wrong search domain -> Check pod's /etc/resolv.conf
```

### Certificate + DNS Mismatch

```bash
# Verify cert SAN matches DNS
openssl s_client -connect order-service.production.svc.cluster.local:443 -servername order-service.production.svc.cluster.local </dev/null 2>/dev/null | openssl x509 -text -noout | grep -A1 "Subject Alternative Name"

# Expected:
# X509v3 Subject Alternative Name:
#     DNS:order-service.production.svc.cluster.local

# If it doesn't match, update the Certificate resource dnsNames
```

---

## Key Takeaways

1. **cert-manager automates certificate lifecycle** in Kubernetes - issuance, renewal, storage
2. **ClusterIssuer** is cluster-wide (shared), **Issuer** is namespace-scoped (isolated)
3. **ACME + Let's Encrypt** works via HTTP-01 (Ingress) or DNS-01 (external DNS provider)
4. **Internal CA Issuer** is best for mTLS between services (no need for Let's Encrypt internally)
5. **CoreDNS** resolves internal service names - certificate SANs must match these DNS names
6. **Certificate SANs** must include all DNS names a service can be reached by (short name, FQDN, etc.)
7. **cert-manager + Dapr** = cert-manager manages root CA, Dapr Sentry issues workload certs from it
8. **ExternalDNS** bridges internal services to external DNS - separate from CoreDNS

---

Next: [07 - Quick Reference and Architecture Diagrams](./07-quick-reference.md)
