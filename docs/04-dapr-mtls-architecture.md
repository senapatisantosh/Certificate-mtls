# 04 - Dapr mTLS Architecture

## Table of Contents
- [What Is Dapr](#what-is-dapr)
- [Dapr's mTLS Architecture](#daprs-mtls-architecture)
- [Sentry: Dapr's Certificate Authority](#sentry-daprs-certificate-authority)
- [SPIFFE Identity in Dapr](#spiffe-identity-in-dapr)
- [Certificate Lifecycle in Dapr](#certificate-lifecycle-in-dapr)
- [How Dapr Service Invocation Uses mTLS](#how-dapr-service-invocation-uses-mtls)
- [Dapr mTLS Configuration](#dapr-mtls-configuration)
- [Access Control Policies](#access-control-policies)
- [Dapr mTLS in Kubernetes vs Self-Hosted](#dapr-mtls-in-kubernetes-vs-self-hosted)
- [Debugging Dapr mTLS Issues](#debugging-dapr-mtls-issues)

---

## What Is Dapr

**Dapr** (Distributed Application Runtime) is a runtime that makes building
microservices easier. It runs as a **sidecar** next to your application.

```
Without Dapr:                          With Dapr:
============                           =========

+----------+     direct call    +----------+
| Service A| =================>| Service B|       Your app talks to Dapr sidecar
+----------+     (you handle   +----------+       Dapr handles all infrastructure:
  Must handle:    TLS, retries,   Must handle:     - Service discovery
  - Service       load balance,   - TLS termination - mTLS encryption
    discovery     circuit break)  - Auth             - Retries / circuit breaking
  - mTLS                          - ...              - Pub/sub, state, secrets
  - Retries                                          - Observability
  - ...

+----------+    localhost    +------+    mTLS    +------+    localhost    +----------+
| Service A| <=============>| Dapr | <===========>| Dapr | <=============>| Service B|
| (your    |   port 3500    |Sidecar|  automatic  |Sidecar|   port 3500    | (your    |
|  code)   |   HTTP/gRPC    |  :A  |  encrypted  |  :B  |   HTTP/gRPC    |  code)   |
+----------+                +------+             +------+                +----------+
                               ^                    ^
                               |                    |
                          mTLS is TRANSPARENT to your application code
                          Your app just calls localhost - Dapr handles the rest
```

---

## Dapr's mTLS Architecture

Dapr has **mTLS enabled by default**. Every sidecar-to-sidecar communication
is automatically encrypted and mutually authenticated.

### The Three Components

```
+------------------------------------------------------------------+
|                        Kubernetes Cluster                         |
|                                                                   |
|  +-------------------+                                           |
|  | Dapr Sentry       |  <-- Certificate Authority (CA)           |
|  | (dapr-sentry)     |      Issues workload certificates         |
|  |                   |      Manages trust domain                  |
|  | Root Cert: self-  |      Handles certificate signing           |
|  | signed or from    |                                           |
|  | cert-manager      |                                           |
|  +---------|---------+                                           |
|            | Signs certs for                                      |
|            v                                                      |
|  +---------|---------+         +--------------------+            |
|  | Dapr Sidecar      |  mTLS  | Dapr Sidecar       |            |
|  | (daprd) for       |<======>| (daprd) for         |            |
|  | Service A         |        | Service B           |            |
|  |                   |        |                     |            |
|  | Has: workload cert|        | Has: workload cert  |            |
|  | SPIFFE ID:        |        | SPIFFE ID:          |            |
|  | spiffe://cluster  |        | spiffe://cluster    |            |
|  |  .local/ns/default|        |  .local/ns/default  |            |
|  |  /dapr-svc-a      |        |  /dapr-svc-b        |            |
|  +---------|---------+         +---------|---------+            |
|            | localhost                    | localhost             |
|            v                             v                       |
|  +-------------------+         +--------------------+            |
|  | Service A (.NET)  |         | Service B (.NET)   |            |
|  | Port 5000         |         | Port 5000          |            |
|  +-------------------+         +--------------------+            |
+------------------------------------------------------------------+
```

### Trust Domain

```
Dapr's trust domain defines the boundary of certificate trust:

  Trust Domain: "cluster.local" (default)

  All sidecars in the same trust domain:
  - Get certs signed by the same Sentry root CA
  - Can communicate via mTLS
  - Are part of the same "zero trust" network

  SPIFFE ID format:
  spiffe://<trust-domain>/ns/<namespace>/<app-id>

  Examples:
  spiffe://cluster.local/ns/default/dapr-orderservice
  spiffe://cluster.local/ns/production/dapr-paymentservice
  spiffe://cluster.local/ns/staging/dapr-orderservice
```

---

## Sentry: Dapr's Certificate Authority

Sentry is Dapr's built-in CA that manages the entire certificate lifecycle.

### Sentry Startup Flow

```
  Sentry Starts
       |
       v
  Does a root cert exist?
       |
    +--+--+
    |     |
   YES    NO
    |      |
    v      v
  Load    Generate self-signed
  existing root CA cert
  root    (RSA 4096 / EC P256)
  cert    Store in Kubernetes
          Secret: dapr-trust-bundle
       |
       v
  Sentry is ready to sign
  workload certificates
       |
       v
  Listen on port 443 (gRPC)
  for CSR requests from sidecars
```

### Sentry Certificate Signing Flow

```
  Dapr Sidecar (daprd)                            Sentry (CA)
  ====================                            ===========

  1. Sidecar starts alongside
     your application pod

  2. Generate ECDSA P-256 key pair
     (private key stays in sidecar memory)

  3. Create CSR ---------------------------------> 4. Validate the request:
     - Include app ID                                - Is the pod/identity valid?
     - Include namespace                             - Check Kubernetes
     - Include trust domain                            ServiceAccount token
     - Signed with private key                       - Verify namespace

                                                   5. Build certificate:
                                                      - Subject: (see below)
                                                      - SAN URI: SPIFFE ID
                                                      - EKU: serverAuth + clientAuth
                                                      - Validity: 24 hours (default)
                                                      - Key Usage: digitalSignature

                                                   6. Sign with Sentry's root key

  7. Receive signed certificate  <---------------- 8. Return signed cert + trust chain
     and CA trust chain

  9. Store in memory
     (never written to disk!)

  10. Use for all mTLS connections
      with other sidecars
```

### What the Workload Certificate Looks Like

```
+------------------------------------------------------------------+
| Dapr Workload Certificate                                        |
+------------------------------------------------------------------+
| Version: 3                                                       |
| Serial:  <random>                                                |
| Issuer:  O=dapr.io, CN=cluster.local                            |
| Subject: O=dapr.io, CN=cluster.local                            |
|                                                                  |
| Validity:                                                        |
|   Not Before: 2025-01-15T10:00:00Z                              |
|   Not After:  2025-01-16T10:00:00Z  (24 hours!)                 |
|                                                                  |
| SAN (Subject Alternative Name):                                  |
|   URI: spiffe://cluster.local/ns/default/dapr-orderservice      |
|   DNS: dapr-orderservice.default.svc.cluster.local               |
|                                                                  |
| Key Usage:        digitalSignature                               |
| Extended Key Usage: serverAuth, clientAuth                       |
| Basic Constraints: CA:FALSE                                      |
+------------------------------------------------------------------+
```

> **Key Design Decisions:**
> - **24-hour validity** reduces blast radius of key compromise
> - **In-memory only** - private keys never hit disk
> - **SPIFFE URI** enables identity-based access control
> - **Both serverAuth + clientAuth** - sidecar acts as both client and server

---

## SPIFFE Identity in Dapr

**SPIFFE** (Secure Production Identity Framework for Everyone) is a standard
for service identity. Dapr uses SPIFFE IDs in certificate SANs.

```
SPIFFE ID Structure:
====================

spiffe://cluster.local/ns/production/dapr-orderservice
|        |              |  |          |
|        trust domain   |  namespace  app-id
|                       |
scheme                 path separator

Components:
- Trust Domain: "cluster.local" (configured in Dapr)
- Namespace:    Kubernetes namespace where the app runs
- App ID:       Dapr app-id annotation on the pod
```

### How SPIFFE IDs Enable Authorization

```
Service A (order-service)                   Service B (payment-service)
SPIFFE: spiffe://cluster.local              SPIFFE: spiffe://cluster.local
        /ns/default/dapr-orderservice               /ns/default/dapr-paymentservice

  1. order-service calls payment-service via Dapr sidecar
  2. Sidecars establish mTLS
  3. payment-service's sidecar reads order-service's SPIFFE ID
  4. Checks access policy: "Is dapr-orderservice allowed to call me?"
  5. If yes -> forward request. If no -> reject with 403.
```

### Namespace Isolation

```
  Namespace: "production"                  Namespace: "staging"
  ========================                 ========================
  spiffe://cluster.local                   spiffe://cluster.local
    /ns/production/dapr-svc-a                /ns/staging/dapr-svc-a
    /ns/production/dapr-svc-b                /ns/staging/dapr-svc-b

  Can communicate with each other           Can communicate with each other
  (same trust domain)                       (same trust domain)

  Can also communicate cross-namespace (if policy allows)
  But access policies can restrict this!
```

---

## Certificate Lifecycle in Dapr

### Automatic Rotation

```
Timeline (default 24-hour workload cert, 1-year root cert):
============================================================

  Hour 0         Hour 12        Hour 24        Hour 36
  |              |              |              |
  v              v              v              v
  Cert issued    70% of cert    Cert expires   New cert
  by Sentry      lifetime       but sidecar    continues
                 reached:       got new cert   working
                 RENEW!         at Hour 12

  Rotation happens at 70% of cert lifetime (configurable)

  Root cert:
  Year 0                                                      Year 1
  |                                                           |
  v                                                           v
  Root issued                        Root rotated             New root
                                     (trust bundle updated)
```

### Rotation Flow

```
  Sidecar                                    Sentry
  =======                                    ======

  Timer fires (70% of cert lifetime)

  1. Generate new key pair

  2. Create new CSR -----------------------> 3. Validate & sign

  4. Receive new cert  <------------------- 5. Return new cert

  6. Atomic swap:
     - Old cert still valid
     - Switch to new cert
     - Old connections continue
       with old cert until they close
     - New connections use new cert

  Zero downtime!
```

---

## How Dapr Service Invocation Uses mTLS

When Service A invokes Service B through Dapr:

```
  Service A          Sidecar A          Sidecar B          Service B
  (.NET app)         (daprd)            (daprd)            (.NET app)
  =========          =========          =========          =========

  1. HTTP POST to
     localhost:3500
     /v1.0/invoke/
     service-b/
     method/process
         |
         v
  2.              Resolve service-b
                  via name resolution
                  (mDNS or Kubernetes DNS)
                       |
                       v
  3.              Establish mTLS
                  to Sidecar B
                  - Present workload cert
                  - Verify B's cert
                  - Check SPIFFE ID
                       |
                       v
  4.              Send request --------> 5. Verify mTLS
                  over encrypted            - Check A's cert
                  channel (gRPC)            - Read SPIFFE ID
                                            - Check access policy
                                                 |
                                                 v
  6.                                        Forward to
                                            localhost:5000
                                            (Service B's port)
                                                 |
                                                 v
  7.                                                        Process
                                                            request
                                                              |
                                                              v
  8.                                        Response  <-----  Return
                                                              result
         |
         v
  9. Receive    <--- Response over   <--- Response over
     response       encrypted channel    encrypted channel
```

### What Your .NET Code Looks Like

```csharp
// Service A calling Service B - NO mTLS CODE NEEDED!
// Dapr handles everything.

using var client = new DaprClientBuilder().Build();

var result = await client.InvokeMethodAsync<Order, OrderResult>(
    "service-b",        // Dapr app-id (maps to SPIFFE ID)
    "process",          // Method name
    new Order { Id = 1, Amount = 99.99m }
);

// That's it! Under the hood:
// 1. Dapr SDK calls localhost:3500 (Dapr sidecar)
// 2. Sidecar resolves "service-b" via name resolution
// 3. Sidecar establishes mTLS with service-b's sidecar
// 4. Both sidecars verify each other's SPIFFE identities
// 5. Request is encrypted in transit
// 6. Response comes back through the same encrypted channel
```

---

## Dapr mTLS Configuration

### Kubernetes: Helm Values

```yaml
# values.yaml for Dapr Helm chart
global:
  mtls:
    enabled: true              # mTLS on/off (default: true)
    workloadCertTTL: "24h"     # Workload cert lifetime
    allowedClockSkew: "15m"    # Clock skew tolerance
    controlPlaneTrustDomain: "cluster.local"  # Trust domain

dapr_sentry:
  # Use your own root cert (instead of auto-generated)
  tls:
    issuer:
      certPEM: |
        -----BEGIN CERTIFICATE-----
        ...your root cert...
        -----END CERTIFICATE-----
      keyPEM: |
        -----BEGIN EC PRIVATE KEY-----
        ...your root key...
        -----END EC PRIVATE KEY-----
    root:
      certPEM: |
        -----BEGIN CERTIFICATE-----
        ...root CA cert...
        -----END CERTIFICATE-----
```

### Self-Hosted Mode: Configuration File

```yaml
# config.yaml
apiVersion: dapr.io/v1alpha1
kind: Configuration
metadata:
  name: daprConfig
spec:
  mtls:
    enabled: true
    workloadCertTTL: "24h"
    allowedClockSkew: "15m"
    # For self-hosted, you must provide certs:
    # Place in ~/.dapr/certs/
    #   ca.crt       - Root CA certificate
    #   issuer.crt   - Issuer certificate
    #   issuer.key   - Issuer private key
```

### Generate Certs for Self-Hosted Dapr

```bash
# Using the Dapr CLI
dapr mtls export -o ./certs

# Or generate your own:
# 1. Generate root CA
openssl ecparam -genkey -name prime256v1 -out root.key
openssl req -new -x509 -key root.key -out root.crt \
  -days 365 -subj "/O=dapr.io/CN=cluster.local"

# 2. Generate issuer cert (signed by root)
openssl ecparam -genkey -name prime256v1 -out issuer.key
openssl req -new -key issuer.key -out issuer.csr \
  -subj "/O=dapr.io/CN=cluster.local"
openssl x509 -req -in issuer.csr -CA root.crt -CAkey root.key \
  -CAcreateserial -out issuer.crt -days 365

# 3. Place in Dapr cert directory
cp root.crt ~/.dapr/certs/ca.crt
cp issuer.crt ~/.dapr/certs/issuer.crt
cp issuer.key ~/.dapr/certs/issuer.key
```

---

## Access Control Policies

Dapr uses SPIFFE identities for fine-grained access control:

```yaml
# Access control configuration
apiVersion: dapr.io/v1alpha1
kind: Configuration
metadata:
  name: appconfig
spec:
  accessControl:
    defaultAction: deny                    # Deny by default (zero trust!)
    trustDomain: "cluster.local"
    policies:
      # Allow order-service to call payment-service
      - appId: dapr-orderservice
        defaultAction: deny
        trustDomain: "cluster.local"
        namespace: "default"
        operations:
          - name: /process-payment         # Specific endpoint
            httpVerb: ["POST"]             # Specific HTTP method
            action: allow

          - name: /refund
            httpVerb: ["POST"]
            action: allow

          - name: /admin/*                 # Wildcard
            httpVerb: ["*"]
            action: deny                   # But deny admin endpoints

      # Allow inventory-service read-only access
      - appId: dapr-inventoryservice
        defaultAction: deny
        trustDomain: "cluster.local"
        namespace: "default"
        operations:
          - name: /stock-level
            httpVerb: ["GET"]              # Read-only
            action: allow
```

### How Policies Are Enforced

```
Incoming mTLS connection from Sidecar A
         |
         v
  1. Extract SPIFFE ID from client cert
     spiffe://cluster.local/ns/default/dapr-orderservice
         |
         v
  2. Parse: trust-domain = "cluster.local"
            namespace = "default"
            app-id = "dapr-orderservice"
         |
         v
  3. Match against access control policies
     - Find policy for appId "dapr-orderservice"
     - Check trust domain matches
     - Check namespace matches
         |
         v
  4. Check operation
     - Request: POST /process-payment
     - Policy: name=/process-payment, httpVerb=[POST], action=allow
     - Result: ALLOW
         |
         v
  5. Forward to application
```

---

## Dapr mTLS in Kubernetes vs Self-Hosted

| Aspect | Kubernetes Mode | Self-Hosted Mode |
|--------|----------------|-----------------|
| **Sentry deployment** | Kubernetes Deployment | Standalone process |
| **Root cert storage** | Kubernetes Secret (`dapr-trust-bundle`) | File system (`~/.dapr/certs/`) |
| **Identity verification** | ServiceAccount token validation | Shared trust bundle |
| **Name resolution** | Kubernetes DNS | mDNS or custom resolver |
| **Cert storage** | In-memory (sidecar) | In-memory (sidecar) |
| **Auto-rotation** | Yes (built-in) | Yes (built-in) |
| **Scaling** | Kubernetes handles | You manage |

### Kubernetes-Specific Flow

```
  Pod Spec (annotated for Dapr):
  ==============================
  apiVersion: apps/v1
  kind: Deployment
  spec:
    template:
      metadata:
        annotations:
          dapr.io/enabled: "true"
          dapr.io/app-id: "orderservice"     <-- Becomes part of SPIFFE ID
          dapr.io/app-port: "5000"
          dapr.io/config: "appconfig"         <-- References access control config
      spec:
        containers:
          - name: orderservice
            image: myapp:latest
            ports:
              - containerPort: 5000

  Kubernetes injects the Dapr sidecar automatically
  (via the dapr-sidecar-injector webhook)

  The sidecar:
  1. Reads app-id from annotation
  2. Gets ServiceAccount token from Kubernetes
  3. Sends CSR + SA token to Sentry
  4. Sentry validates SA token with Kubernetes API
  5. Sentry issues workload cert with SPIFFE ID
  6. Sidecar starts serving with mTLS
```

---

## Debugging Dapr mTLS Issues

### Check mTLS Status

```bash
# Check if mTLS is enabled
dapr mtls -k
# Output: Mutual TLS is enabled in your Kubernetes cluster

# Export current root cert
dapr mtls export -o ./exported-certs

# Check Sentry logs
kubectl logs -l app=dapr-sentry -n dapr-system

# Check sidecar logs for cert issues
kubectl logs <pod-name> -c daprd
```

### Common Issues and Solutions

```
Issue: "certificate signed by unknown authority"
=================================================
Cause: Trust bundle not propagated to sidecar
Fix:   Restart the pod (sidecar will fetch new cert)
       kubectl rollout restart deployment/<app>

Issue: "certificate has expired"
================================
Cause: Clock skew or Sentry unavailable during renewal
Fix:   Check NTP sync, verify Sentry is running
       kubectl get pods -n dapr-system

Issue: "access denied by policy"
================================
Cause: Access control policy doesn't allow this call
Fix:   Check Configuration resource, verify appId and operation match
       kubectl get configuration <config-name> -o yaml

Issue: Sidecar can't reach Sentry
==================================
Cause: Network policy blocking, Sentry not running
Fix:   kubectl get pods -n dapr-system
       kubectl get svc -n dapr-system
       Verify port 443 is accessible
```

### Verify Certificate Contents

```bash
# Get the workload cert from a running sidecar
kubectl exec <pod> -c daprd -- cat /var/run/secrets/dapr.io/tls/cert.pem \
  | openssl x509 -text -noout

# Or use Dapr dashboard
dapr dashboard -k
# Navigate to Components -> Configuration
```

---

## Key Takeaways

1. **Sentry is Dapr's built-in CA** - issues short-lived (24h) workload certs automatically
2. **SPIFFE IDs** in SAN URIs are how Dapr identifies workloads: `spiffe://<domain>/ns/<ns>/<app-id>`
3. **mTLS is enabled by default** - your app code doesn't need any TLS logic
4. **Zero-trust access control** uses SPIFFE identities for fine-grained per-endpoint policies
5. **Auto-rotation at 70%** of cert lifetime ensures zero-downtime certificate updates
6. **Private keys stay in memory** - never written to disk, regenerated on each rotation
7. **Trust domain** defines the boundary - all services in the same domain can communicate (if policies allow)

---

Next: [05 - .NET Integration with mTLS and Dapr](./05-dotnet-mtls-dapr-integration.md)
