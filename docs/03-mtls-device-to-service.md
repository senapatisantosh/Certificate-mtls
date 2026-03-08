# 03 - mTLS: Device-to-Service Authentication

## Table of Contents
- [What Is mTLS and Why It Exists](#what-is-mtls-and-why-it-exists)
- [mTLS Handshake Step by Step](#mtls-handshake-step-by-step)
- [Device Certificate Provisioning](#device-certificate-provisioning)
- [Architecture Patterns](#architecture-patterns)
- [Security Decisions from Client Certs](#security-decisions-from-client-certs)
- [Certificate Pinning vs Chain Validation](#certificate-pinning-vs-chain-validation)
- [Common Pitfalls](#common-pitfalls)

---

## What Is mTLS and Why It Exists

**Standard TLS** = Server proves its identity to the client (one-way).
**mTLS (Mutual TLS)** = Both sides prove their identity to each other (two-way).

```
Standard TLS:                          mTLS:
=============                          =====

Client -----> Server                   Client <----> Server
  "I trust     "Here's my               "Here's my    "Here's my
   you based    certificate"              certificate"  certificate"
   on your
   cert"                                 BOTH sides verify
                                         the other's identity
Only SERVER
is authenticated                        BOTH are authenticated
```

### When Do You Need mTLS?

| Scenario | TLS | mTLS |
|----------|-----|------|
| Browser to web server | Yes | No (users auth with passwords/tokens) |
| Mobile app to API | Yes | Maybe (cert-based device auth) |
| IoT device to cloud service | Yes | **Yes** (devices have certs, no passwords) |
| Service-to-service (microservices) | Yes | **Yes** (zero-trust networking) |
| Kubernetes pod-to-pod | Yes | **Yes** (Dapr, Istio, Linkerd) |

> **Key Insight:** mTLS replaces API keys, tokens, and passwords with
> cryptographic identity. The device's private key IS its credential,
> and it never leaves the device.

---

## mTLS Handshake Step by Step

```
  Device (Client)                                  Service (Server)
  ===============                                  ================

  1. ClientHello ------------------------------>
     - TLS 1.3
     - Supported ciphers
     - SNI: api.iot.example.com

                                                   2. ServerHello
                                           <------    - Selected cipher
                                                      - Server certificate chain
                                                      - CertificateRequest  <--- THIS IS THE mTLS PART!
                                                        (list of acceptable CAs)

  3. Verify server cert chain
     - Is the server who it claims to be?
     - Check SAN matches hostname
     - Check chain to trusted root

  4. Client Certificate   --------------------->   5. Verify client cert chain
     - Device's certificate chain                     - Is the device who it claims?
     - CertificateVerify                              - Check chain to trusted CA
       (signed with device's private key,             - Check cert not expired
        proves possession of private key)             - Check cert not revoked
                                                      - Read device metadata from cert
                                                      - Apply authorization policies

  6. Both derive session keys

  7. [Encrypted traffic]  <===================>   [Encrypted traffic]
     Device is authenticated                      Service is authenticated
     Service is authenticated                     Device is authenticated
```

### The CertificateRequest Message (Server -> Client)

This is what triggers the "mutual" part. The server says:

```
CertificateRequest {
    certificate_authorities: [
        "CN=Acme IoT Root CA, O=Acme Corp",       -- "I trust devices signed by this CA"
        "CN=Acme IoT Intermediate CA, O=Acme Corp" -- "Or this one"
    ],
    signature_algorithms: [
        ecdsa_secp256r1_sha256,                    -- "Use these algorithms"
        rsa_pss_rsae_sha256
    ],
    certificate_extensions: [...]                  -- Optional: required extensions
}
```

The client then selects a certificate that chains to one of these CAs and sends it.

---

## Device Certificate Provisioning

Before mTLS can work, each device needs a certificate. Here are the common patterns:

### Pattern 1: Factory Provisioning

```
  Manufacturing Line                    Your PKI / CA
  ==================                    ==============

  1. Device generates key pair
     on its secure element (TPM/HSM)
         |
         v
  2. Device creates CSR  ------------->  3. CA signs certificate
     (public key + device info)             with device identity
                                    <---  4. Returns certificate
  5. Certificate stored in
     device's secure storage

  Device ships with:
  - Private key (in TPM, non-exportable)
  - Device certificate (signed by your CA)
  - CA certificate chain (for verifying servers)
```

### Pattern 2: Enrollment / Bootstrap

```
  New Device                   Enrollment Service              Your CA
  ==========                   ==================              =======

  1. Device has a bootstrap
     credential (one-time token,
     or manufacturer cert)
         |
         v
  2. Connect with bootstrap
     credential ------------>  3. Verify bootstrap
                                  credential
                                     |
                                     v
                               4. Request cert from CA -----> 5. Issue device cert
                                                         <---    (with device metadata
                                                                  in Subject/SAN)
                          <--- 6. Return device cert
                                  + CA chain

  7. Store device cert
  8. Delete bootstrap credential
  9. Future connections use
     the device cert for mTLS
```

### Pattern 3: ACME Device Attestation (Emerging)

Using ACME protocol with device attestation challenges:

```
  Device with TPM              ACME Server              CA
  ================             ===========              ==
  1. Generate key in TPM
  2. Request cert via ACME ---> 3. Challenge: prove
                                   you have a valid TPM
  4. TPM attestation    ------> 5. Verify attestation
     (signed by TPM's               against known TPM
      endorsement key)               manufacturers
                                6. Issue cert <---------> 7. Sign
                           <--- 8. Return cert
```

---

## Architecture Patterns

### Pattern A: Direct mTLS (Device -> Service)

```
  +--------+         mTLS          +----------+
  | Device | <===================> | Service  |
  +--------+                       +----------+
  Has: device cert                 Has: server cert
  Trusts: service CA               Trusts: device CA
  Validates: server cert           Validates: device cert
                                   Reads: device metadata
                                   Makes: authz decisions
```

**Pros:** Simple, no intermediaries
**Cons:** Every service needs cert validation logic, hard to scale policies

### Pattern B: mTLS Gateway / API Gateway

```
  +--------+     mTLS      +---------+     internal     +----------+
  | Device | <============>| Gateway | <===============>| Service  |
  +--------+               +---------+                  +----------+
                            |                            |
                            | Terminates mTLS            | Receives device
                            | Validates device cert      | identity as header:
                            | Extracts metadata          | X-Device-ID: dev-042
                            | Applies policies           | X-Device-Fleet: east
                            | Forwards identity          | X-Device-OU: sensors
```

**Pros:** Centralized cert validation, services stay simple
**Cons:** Gateway is a single point of failure, internal traffic may be unencrypted

### Pattern C: Service Mesh mTLS (Dapr / Istio)

```
  +-----------+    mTLS    +-----+    mTLS    +-----+    +-----------+
  | Service A | <========> |Sidecar| <======> |Sidecar| <=> | Service B |
  +-----------+            +-----+            +-----+    +-----------+
                              |                  |
                              | Dapr/Envoy       | Dapr/Envoy
                              | handles all      | handles all
                              | mTLS automatically| mTLS automatically
                              | App code is      | App code is
                              | unaware of certs | unaware of certs
```

**Pros:** Zero app-level cert management, automatic rotation, policy enforcement
**Cons:** Sidecar overhead, additional infrastructure (covered in Dapr doc)

---

## Security Decisions from Client Certs

When a device connects via mTLS, here's the decision tree your service should implement:

```
  Device connects via mTLS
           |
           v
  +-- Chain Validation (TLS library handles this) --+
  | 1. Is cert signed by a trusted CA?              |
  | 2. Is the full chain valid?                     |
  | 3. Is the cert not expired?                     |
  | 4. Is the cert not revoked (CRL/OCSP)?          |
  +------ PASS / FAIL ----------------------------+
           |                        |
          PASS                    FAIL --> 403 Forbidden
           |
           v
  +-- Application-Level Checks --+
  | 5. Does EKU include clientAuth?  --> No --> REJECT
  | 6. Is device in our registry?    --> No --> REJECT (unknown device)
  | 7. Is device's fleet allowed?    --> No --> REJECT (wrong tenant)
  +-------------------------------+
           |
          PASS
           |
           v
  +-- Authorization --+
  | Read cert metadata:
  | - Subject.CN  --> device ID
  | - Subject.OU  --> device fleet/role
  | - SAN URI     --> SPIFFE identity
  | - Custom OID  --> device type
  |
  | Apply policies:
  | - "sensors" can only POST /telemetry
  | - "actuators" can POST /commands
  | - "admin" can access /management
  +-------------------+
           |
           v
  REQUEST PROCESSED with device context
```

### Example: Authorization Matrix

```
+-------------------+------------------+------------------+------------------+
| Cert Subject.OU   | POST /telemetry  | GET /commands    | POST /admin      |
+-------------------+------------------+------------------+------------------+
| IoT-Sensors       |       ALLOW      |      DENY        |      DENY        |
| IoT-Actuators     |       ALLOW      |      ALLOW       |      DENY        |
| IoT-Admin         |       ALLOW      |      ALLOW       |      ALLOW       |
| (unknown OU)      |       DENY       |      DENY        |      DENY        |
+-------------------+------------------+------------------+------------------+
```

---

## Certificate Pinning vs Chain Validation

Two approaches to trusting client certificates:

### Chain Validation (Recommended for most cases)

```
Trust any cert signed by our CA
         |
         v
  Root CA: "Acme IoT Root"
     |
     +-- Intermediate: "Acme IoT Fleet-East CA"
     |      |
     |      +-- device-001 cert  --> TRUSTED
     |      +-- device-002 cert  --> TRUSTED
     |      +-- new-device cert  --> TRUSTED (auto-trusted!)
     |
     +-- Intermediate: "Acme IoT Fleet-West CA"
            |
            +-- device-101 cert  --> TRUSTED
```

**Pros:** New devices automatically trusted, scales to millions
**Cons:** Any cert from the CA is trusted (must trust the CA fully)

### Certificate Pinning (High-security scenarios)

```
Trust ONLY these specific cert thumbprints:
  - SHA256:A1B2C3... (device-001)
  - SHA256:D4E5F6... (device-002)
  - SHA256:G7H8I9... (device-003)

  device-001 cert --> thumbprint matches --> TRUSTED
  device-004 cert --> thumbprint NOT in list --> REJECTED
                     (even though CA is valid!)
```

**Pros:** Maximum control, compromised CA cannot issue new trusted certs
**Cons:** Must register each device individually, no auto-trust

### Hybrid: Chain + Allowlist

```
1. Validate chain (cert signed by trusted CA)
2. AND check device ID against allowlist/registry
3. AND check cert is not on deny list

This gives you:
- CA-level trust boundary (chain validation)
- Individual device control (registry lookup)
- Revocation capability (deny list)
```

---

## Common Pitfalls

### 1. Private Key Storage
```
BAD:  Private key in environment variable or config file
BAD:  Private key with world-readable permissions
GOOD: Private key in TPM/HSM (hardware)
GOOD: Private key in Kubernetes Secret (encrypted at rest)
GOOD: Private key in Azure Key Vault / AWS ACM / GCP CAS
```

### 2. Certificate Rotation
```
BAD:  Long-lived certs (years) with manual renewal
BAD:  No monitoring for cert expiry
GOOD: Short-lived certs (hours/days) with automatic rotation
GOOD: Dapr auto-rotates workload certs every 24 hours by default
GOOD: cert-manager handles renewal automatically
```

### 3. Revocation Checking
```
BAD:  No revocation checking (compromised device stays trusted)
BAD:  Soft-fail OCSP (treat "can't reach OCSP" as "not revoked")
GOOD: OCSP stapling on the server side
GOOD: Short-lived certs (revocation becomes less critical)
GOOD: Device registry with active/inactive status
```

### 4. Trust Store Management
```
BAD:  Trusting the system trust store for device auth
      (any public CA could issue a "device" cert)
GOOD: Separate trust store with ONLY your device CA(s)
GOOD: Kubernetes: mount CA cert as a ConfigMap/Secret
```

### 5. Missing EKU Check
```
BAD:  Accepting any valid cert as a client cert
      (a server cert shouldn't authenticate as a client)
GOOD: Check that client cert has extendedKeyUsage: clientAuth
```

---

## Key Takeaways

1. **mTLS = both sides present certificates** - the server sends a `CertificateRequest`
   to trigger client cert presentation
2. **Device certs encode identity** in Subject fields and SANs - use this for authz
3. **Three provisioning patterns:** factory, enrollment/bootstrap, ACME attestation
4. **Three architecture patterns:** direct mTLS, gateway termination, service mesh (Dapr)
5. **Chain validation scales**, pinning gives max control, hybrid is often best
6. **Short-lived certs + auto-rotation** reduces the revocation problem
7. **Always use a dedicated trust store** for device CAs (not the system store)

---

Next: [04 - Dapr mTLS Architecture](./04-dapr-mtls-architecture.md)
