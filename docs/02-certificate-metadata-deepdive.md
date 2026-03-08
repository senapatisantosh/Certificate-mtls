# 02 - Certificate Metadata Deep Dive

## Table of Contents
- [X.509 v3 Certificate Structure](#x509-v3-certificate-structure)
- [Standard Fields](#standard-fields)
- [Extensions (The Powerful Part)](#extensions-the-powerful-part)
- [What Metadata You Can Read at Runtime](#what-metadata-you-can-read-at-runtime)
- [Decision-Making from Certificate Metadata](#decision-making-from-certificate-metadata)
- [Reading Certs in .NET](#reading-certs-in-net)
- [Reading Certs with OpenSSL](#reading-certs-with-openssl)

---

## X.509 v3 Certificate Structure

An X.509 certificate is encoded in ASN.1 (Abstract Syntax Notation One) and has a well-defined
structure. Here's every field you can read and what it means:

```
Certificate ::= SEQUENCE {
    tbsCertificate       TBSCertificate,       -- "To Be Signed" data
    signatureAlgorithm   AlgorithmIdentifier,  -- Algorithm CA used to sign
    signatureValue       BIT STRING            -- The actual signature bytes
}

TBSCertificate ::= SEQUENCE {
    version         [0]  INTEGER DEFAULT v1,   -- Almost always v3 (0x2)
    serialNumber         INTEGER,              -- Unique per CA
    signature            AlgorithmIdentifier,  -- Must match outer signatureAlgorithm
    issuer               Name,                 -- DN of the CA
    validity             Validity,             -- NotBefore + NotAfter
    subject              Name,                 -- DN of the entity
    subjectPublicKeyInfo SubjectPublicKeyInfo, -- Public key + algorithm
    extensions      [3]  Extensions OPTIONAL   -- v3 extensions (critical + non-critical)
}
```

---

## Standard Fields

### 1. Version
- Always `3` (encoded as `0x2`) for modern certs
- v3 enables extensions (SANs, Key Usage, etc.)

### 2. Serial Number
```
Serial: 04:E3:A2:1B:7F:00:99:...
```
- **Unique identifier** within a CA's scope
- Used for revocation (CRL lists serial numbers)
- Can be used to track/audit specific certificates

### 3. Signature Algorithm
```
sha256WithRSAEncryption    -- Most common
ecdsa-with-SHA256          -- Modern, preferred
ecdsa-with-SHA384          -- Higher security
```

### 4. Issuer (Distinguished Name)
```
C  = US                     -- Country
O  = Let's Encrypt          -- Organization
CN = R3                     -- Common Name (intermediate CA name)
```
**What you can derive:** Which CA issued this cert. Useful for enforcing
"only trust certs from our internal CA" policies.

### 5. Validity Period
```
Not Before: 2025-01-15T00:00:00Z
Not After:  2025-04-15T23:59:59Z
```
- Let's Encrypt: 90 days
- Internal CAs: configurable (Dapr default: 1 year for workload certs)
- **Critical for mTLS:** Expired certs should be rejected

### 6. Subject (Distinguished Name)

The subject identifies **who/what this certificate represents**.

```
Full DN (Distinguished Name) fields:
=====================================
CN  = Common Name          "api.example.com" or "device-12345"
O   = Organization         "Acme Corp"
OU  = Organizational Unit  "IoT Devices" or "Backend Services"
C   = Country              "US"
ST  = State/Province       "California"
L   = Locality             "San Francisco"
E   = Email                "admin@example.com"

SERIALNUMBER = "DEV-2025-001"   -- Device serial (not cert serial!)
```

> **For mTLS device auth:** The Subject fields are your primary source of device
> identity. You can encode device ID, device type, organization, and more.

### 7. Subject Public Key Info
```
Algorithm: id-ecPublicKey (P-256)
Public Key: 04:A1:B2:C3:D4:... (65 bytes for P-256 uncompressed)
```

---

## Extensions (The Powerful Part)

Extensions are where most of the actionable metadata lives. Each extension can be
marked **critical** (must be understood) or **non-critical** (can be ignored if not understood).

### Subject Alternative Names (SAN) - CRITICAL FOR mTLS

```
Extension: subjectAltName (OID: 2.5.29.17)
Critical: NO (but universally checked)

Types of SANs:
==============
DNS:     api.example.com          -- Domain name
DNS:     *.example.com            -- Wildcard
IP:      192.168.1.100            -- IP address
Email:   device@example.com       -- RFC 822 name
URI:     spiffe://cluster.local/ns/default/sa/myapp  -- SPIFFE ID (used by Dapr!)
DirName: CN=device-123,O=fleet-a  -- Directory name
```

> **SPIFFE ID in SAN:** Dapr encodes workload identity as a SPIFFE URI in the SAN.
> This is how Dapr services identify each other in mTLS.
> Format: `spiffe://<trust-domain>/ns/<namespace>/sa/<app-id>`

### Key Usage

```
Extension: keyUsage (OID: 2.5.29.15)
Critical: YES

Bits:
  digitalSignature  (0) -- Sign data (TLS handshake, mTLS auth)
  keyEncipherment   (2) -- Encrypt keys (RSA key exchange)
  dataEncipherment  (3) -- Encrypt data directly
  keyAgreement      (4) -- Diffie-Hellman key agreement
  keyCertSign       (5) -- Sign other certificates (CA certs only!)
  cRLSign           (6) -- Sign CRLs (CA certs only!)
```

**For mTLS leaf certs:** You want `digitalSignature` + `keyEncipherment`
**For CA certs:** You want `keyCertSign` + `cRLSign`

### Extended Key Usage (EKU)

```
Extension: extKeyUsage (OID: 2.5.29.37)
Critical: NO (usually)

OID Values:
  serverAuth    (1.3.6.1.5.5.7.3.1) -- TLS server certificate
  clientAuth    (1.3.6.1.5.5.7.3.2) -- TLS client certificate (mTLS!)
  codeSigning   (1.3.6.1.5.5.7.3.3) -- Code signing
  emailProtect  (1.3.6.1.5.5.7.3.4) -- S/MIME
```

> **For mTLS:** Both `serverAuth` AND `clientAuth` should be present on
> certificates used in mutual TLS. A cert with only `serverAuth` cannot
> be used as a client cert (and vice versa).

### Basic Constraints

```
Extension: basicConstraints (OID: 2.5.29.19)
Critical: YES

CA: TRUE/FALSE       -- Is this a CA certificate?
pathLenConstraint: N -- Max number of CAs below this one
```

- Leaf/end-entity certs: `CA:FALSE`
- Intermediate CAs: `CA:TRUE, pathlen:0` (can only sign leaf certs)
- Root CAs: `CA:TRUE` (no pathlen limit)

### Authority Key Identifier (AKI) & Subject Key Identifier (SKI)

```
AKI: keyIdentifier = 14:2E:B3:17:...  -- Hash of issuer's public key
SKI:                  7A:3B:1C:92:...  -- Hash of this cert's public key
```

Used to build the chain: child cert's AKI = parent cert's SKI.

### Certificate Policies

```
Extension: certificatePolicies (OID: 2.5.29.32)

Policy: 2.23.140.1.2.1     -- Domain Validated (DV)
Policy: 2.23.140.1.2.2     -- Organization Validated (OV)
Policy: 2.23.140.1.1       -- Extended Validation (EV)

Custom: 1.3.6.1.4.1.XXXXX  -- Your organization's custom policy OID
```

Let's Encrypt issues **DV (Domain Validated)** certs only - they prove domain control,
not organizational identity.

### CRL Distribution Points & OCSP

```
CRL:  http://r3.o.lencr.org                    -- Download revocation list
OCSP: http://r3.o.lencr.org                    -- Real-time revocation check
```

### Custom Extensions (OID-based)

You can define custom extensions using your organization's OID arc:

```
Example custom extensions for device certificates:
===================================================
OID: 1.3.6.1.4.1.XXXXX.1.1  ->  Device Type: "temperature-sensor"
OID: 1.3.6.1.4.1.XXXXX.1.2  ->  Firmware Version: "2.3.1"
OID: 1.3.6.1.4.1.XXXXX.1.3  ->  Fleet ID: "production-east"
OID: 1.3.6.1.4.1.XXXXX.1.4  ->  Provisioning Date: "2025-01-15"
```

---

## What Metadata You Can Read at Runtime

Here is a complete map of what's readable and what decisions you can make:

```
+---------------------------+-------------------------------------------+---------------------------+
| Certificate Field         | Example Value                             | Decision You Can Make     |
+---------------------------+-------------------------------------------+---------------------------+
| Subject CN                | "device-temp-sensor-042"                  | Identify the device       |
| Subject O                 | "Acme Corp"                               | Verify organization       |
| Subject OU                | "IoT-Fleet-East"                          | Route to correct service  |
| Subject SERIALNUMBER      | "SN-2025-00042"                           | Map to device registry    |
| SAN DNS                   | "device042.iot.example.com"               | Hostname validation       |
| SAN URI (SPIFFE)          | "spiffe://example.com/device/042"         | Workload identity (Dapr)  |
| SAN IP                    | "10.0.1.42"                               | Network-level validation  |
| Issuer CN                 | "Acme IoT Intermediate CA"                | Verify issuing CA         |
| Issuer O                  | "Acme Corp"                               | Trust boundary check      |
| Serial Number             | "0A:1B:2C:..."                            | Audit trail, revocation   |
| Not Before / Not After    | "2025-01-15" / "2025-04-15"               | Freshness check           |
| EKU                       | clientAuth + serverAuth                   | Role-based access         |
| Key Usage                 | digitalSignature                          | Operation permissions     |
| Thumbprint (SHA-256)      | "A1B2C3D4..."                             | Certificate pinning       |
| Public Key Hash           | "pin-sha256=..."                          | HPKP-style pinning        |
| Custom OID Extensions     | "fleet:production-east"                   | Custom authorization      |
+---------------------------+-------------------------------------------+---------------------------+
```

---

## Decision-Making from Certificate Metadata

### Pattern: Multi-Tenant Device Authorization

```
Incoming mTLS connection from device
         |
         v
  Read client certificate
         |
         +---> Subject.OU = "Fleet-East"  ---> Route to East backend
         |
         +---> Subject.OU = "Fleet-West"  ---> Route to West backend
         |
         +---> SAN URI contains "admin"    ---> Grant admin privileges
         |
         +---> Issuer.CN = "Unknown CA"    ---> REJECT
         |
         +---> EKU missing clientAuth      ---> REJECT
         |
         +---> Not After < now             ---> REJECT (expired)
         |
         +---> Thumbprint in revocation DB ---> REJECT (revoked)
         |
         v
  ALLOW + apply policies based on metadata
```

### Pattern: Certificate-Based RBAC

```csharp
// Pseudo-code for role extraction from cert
var role = cert.Subject.OU switch
{
    "admin-devices"    => Role.Admin,
    "sensor-devices"   => Role.ReadOnly,
    "actuator-devices" => Role.ReadWrite,
    _                  => Role.Denied
};
```

---

## Reading Certs in .NET

```csharp
using System.Security.Cryptography.X509Certificates;

// Load from PFX file
var cert = new X509Certificate2("device.pfx", "password");

// ---- Standard Fields ----
Console.WriteLine($"Subject:        {cert.Subject}");
// Output: "CN=device-042, OU=IoT-Fleet-East, O=Acme Corp"

Console.WriteLine($"Issuer:         {cert.Issuer}");
// Output: "CN=Acme IoT CA, O=Acme Corp"

Console.WriteLine($"Serial:         {cert.SerialNumber}");
Console.WriteLine($"Thumbprint:     {cert.Thumbprint}");
Console.WriteLine($"Not Before:     {cert.NotBefore}");
Console.WriteLine($"Not After:      {cert.NotAfter}");
Console.WriteLine($"Algorithm:      {cert.SignatureAlgorithm.FriendlyName}");
Console.WriteLine($"Has Private Key:{cert.HasPrivateKey}");

// ---- Parse Subject Fields ----
var subjectName = new X500DistinguishedName(cert.SubjectName.RawData);
// Or parse manually:
string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
string dns = cert.GetNameInfo(X509NameType.DnsName, false);

// ---- Extensions ----
foreach (var ext in cert.Extensions)
{
    Console.WriteLine($"OID: {ext.Oid.Value} ({ext.Oid.FriendlyName})");
    Console.WriteLine($"  Critical: {ext.Critical}");

    switch (ext)
    {
        case X509SubjectAlternativeNameExtension san:
            foreach (var name in san.EnumerateDnsNames())
                Console.WriteLine($"  SAN DNS: {name}");
            break;

        case X509KeyUsageExtension ku:
            Console.WriteLine($"  Key Usage: {ku.KeyUsages}");
            break;

        case X509EnhancedKeyUsageExtension eku:
            foreach (var oid in eku.EnhancedKeyUsages)
                Console.WriteLine($"  EKU: {oid.FriendlyName} ({oid.Value})");
            break;

        case X509BasicConstraintsExtension bc:
            Console.WriteLine($"  CA: {bc.CertificateAuthority}");
            Console.WriteLine($"  Path Length: {bc.PathLengthConstraint}");
            break;
    }
}

// ---- Get SPIFFE ID from SAN URI (for Dapr) ----
var sanExt = cert.Extensions["2.5.29.17"] as X509SubjectAlternativeNameExtension;
if (sanExt != null)
{
    // In .NET 8+, you can enumerate URIs directly
    // For older versions, parse the ASN.1 manually or use a library
}
```

---

## Reading Certs with OpenSSL

```bash
# View all certificate details
openssl x509 -in cert.pem -text -noout

# View just the subject
openssl x509 -in cert.pem -subject -noout
# Output: subject= /CN=device-042/OU=IoT-Fleet-East/O=Acme Corp

# View just the issuer
openssl x509 -in cert.pem -issuer -noout

# View SANs
openssl x509 -in cert.pem -ext subjectAltName -noout

# View all extensions
openssl x509 -in cert.pem -ext keyUsage,extendedKeyUsage,basicConstraints -noout

# View certificate fingerprint
openssl x509 -in cert.pem -fingerprint -sha256 -noout

# View serial number
openssl x509 -in cert.pem -serial -noout

# View validity dates
openssl x509 -in cert.pem -dates -noout

# Verify a certificate chain
openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem

# Inspect a PFX file
openssl pkcs12 -in cert.pfx -info -nokeys

# Convert PFX to PEM
openssl pkcs12 -in cert.pfx -out cert.pem -nodes
```

---

## Key Takeaways

1. **Subject + SAN** = Who the cert identifies (device ID, service name, SPIFFE URI)
2. **Issuer** = Who vouches for this identity (your CA or Let's Encrypt)
3. **EKU** = What the cert is allowed to do (`clientAuth` for mTLS client, `serverAuth` for server)
4. **Custom extensions** = Encode any metadata using custom OIDs (fleet, firmware, role)
5. **Thumbprint** = Unique fingerprint for certificate pinning
6. **SAN URI with SPIFFE** = How Dapr and service meshes identify workloads
7. **.NET `X509Certificate2`** = Your primary tool for reading all this at runtime

---

Next: [03 - mTLS Device-to-Service Authentication](./03-mtls-device-to-service.md)
