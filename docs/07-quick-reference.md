# 07 - Quick Reference & Architecture Diagrams

## Complete End-to-End Architecture

```
                           INTERNET
                              |
                              v
                    +-------------------+
                    | Public DNS        |
                    | (Route53/CloudDNS)|
                    | api.example.com   |
                    |  -> LoadBalancer  |
                    +--------+----------+
                             |
+============================|=============================================+
|                    KUBERNETES CLUSTER                                     |
|                            |                                              |
|  +--------+    +-----------v-----------+    +-------------------+        |
|  | cert-  |    | Ingress Controller    |    | CoreDNS           |        |
|  | manager|--->| (nginx/traefik)       |    | Resolves internal |        |
|  |        |    | TLS termination with  |    | *.svc.cluster     |        |
|  | Issues |    | Let's Encrypt cert    |    |  .local names     |        |
|  | certs  |    +-----------+-----------+    +--------+----------+        |
|  +---+----+                |                         |                    |
|      |                     v                         |                    |
|      |    +------------------------------------------|---+                |
|      |    |  Namespace: production                   |   |                |
|      |    |                                          |   |                |
|      |    |  +------+   mTLS    +------+             |   |                |
|      |    |  |Dapr  |<=========>|Dapr  |             |   |                |
|      |    |  |Side- |  (auto)   |Side- |             |   |                |
|      |    |  |car A |           |car B |             |   |                |
|      |    |  +--+---+           +--+---+             |   |                |
|      |    |     |                  |                  |   |                |
|      |    |  +--v---+           +--v---+             |   |                |
|      |    |  |Order |           |Paymnt|             |   |                |
|      |    |  |.NET  |           |.NET  |             |   |                |
|      |    |  |Svc   |           |Svc   |             |   |                |
|      |    |  +------+           +------+             |   |                |
|      |    +------------------------------------------+---+                |
|      |                                                                    |
|      |    +------------------+    +------------------+                    |
|      +--->| Dapr Sentry      |    | Secrets (TLS)    |                    |
|           | (CA for sidecars)|    | tls.crt, tls.key |                    |
|           | Uses root CA from|    | Created by       |                    |
|           | cert-manager     |    | cert-manager     |                    |
|           +------------------+    +------------------+                    |
+=========================================================================+
```

---

## Certificate Flow Cheat Sheet

### Who Issues What?

```
+----------------------+---------------------------+---------------------------+
| Certificate Type     | Issued By                 | Used For                  |
+----------------------+---------------------------+---------------------------+
| External TLS         | Let's Encrypt via         | Ingress HTTPS             |
| (api.example.com)    | cert-manager ACME         | termination               |
+----------------------+---------------------------+---------------------------+
| Internal service     | cert-manager Internal     | Service-to-service        |
| mTLS certs           | CA Issuer                 | mTLS (without Dapr)       |
+----------------------+---------------------------+---------------------------+
| Dapr workload        | Dapr Sentry               | Sidecar-to-sidecar        |
| certs                | (using root from          | automatic mTLS            |
|                      |  cert-manager or self)    |                           |
+----------------------+---------------------------+---------------------------+
| Dapr root CA         | cert-manager self-signed  | Trust anchor for          |
|                      | or external CA            | Dapr Sentry               |
+----------------------+---------------------------+---------------------------+
| K8s component certs  | kubeadm / managed K8s     | API server, etcd,         |
| (don't touch these)  | provider                  | kubelet communication     |
+----------------------+---------------------------+---------------------------+
| Device certs (IoT)   | Your device CA (may be    | Device-to-service         |
|                      | managed by cert-manager)  | mTLS authentication       |
+----------------------+---------------------------+---------------------------+
```

---

## Decision Matrix: Which Approach to Use

### TLS Certificate Selection

```
Do you need certs for external traffic (internet-facing)?
  YES --> Use cert-manager + Let's Encrypt ClusterIssuer
          Challenge: HTTP-01 (standard) or DNS-01 (wildcards)

Do you need certs for internal service-to-service?
  YES --> Are you using Dapr or a service mesh?
          YES --> Dapr/Istio handles it automatically
                  (optionally use cert-manager for root CA)
          NO  --> Use cert-manager Internal CA Issuer
                  Issue certs with clientAuth + serverAuth EKU

Do you need certs for device-to-service (IoT)?
  YES --> Use cert-manager Internal CA Issuer
          Or your own PKI with device enrollment
          Issue device certs with clientAuth EKU
```

---

## OpenSSL Command Cheat Sheet

```bash
# ===== VIEWING CERTIFICATES =====
openssl x509 -in cert.pem -text -noout                  # Full details
openssl x509 -in cert.pem -subject -noout               # Subject only
openssl x509 -in cert.pem -issuer -noout                # Issuer only
openssl x509 -in cert.pem -dates -noout                 # Validity dates
openssl x509 -in cert.pem -serial -noout                # Serial number
openssl x509 -in cert.pem -fingerprint -sha256 -noout   # Thumbprint
openssl x509 -in cert.pem -ext subjectAltName -noout    # SANs

# ===== GENERATING KEYS =====
openssl ecparam -genkey -name prime256v1 -out key.pem    # ECDSA P-256
openssl genrsa -out key.pem 2048                          # RSA 2048

# ===== CREATING CSR =====
openssl req -new -key key.pem -out csr.pem \
  -subj "/CN=my-service/O=My Org/OU=Engineering"

# ===== SELF-SIGNED CA =====
openssl req -new -x509 -key ca.key -out ca.crt \
  -days 3650 -subj "/CN=My Root CA/O=My Org"

# ===== SIGN A CERT =====
openssl x509 -req -in csr.pem -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out cert.pem -days 365 -extfile ext.cnf

# ===== VERIFY CHAIN =====
openssl verify -CAfile ca.crt -untrusted intermediate.crt cert.pem

# ===== CONVERT FORMATS =====
# PEM -> PFX (for .NET)
openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem \
  -certfile ca.crt -passout pass:mypassword

# PFX -> PEM
openssl pkcs12 -in cert.pfx -out cert.pem -nodes

# DER -> PEM
openssl x509 -in cert.der -inform DER -out cert.pem -outform PEM

# ===== TEST TLS CONNECTION =====
openssl s_client -connect host:443 -servername host       # Standard TLS
openssl s_client -connect host:443 -cert client.crt \     # mTLS
  -key client.key -CAfile ca.crt

# ===== INSPECT REMOTE CERT =====
echo | openssl s_client -connect api.example.com:443 2>/dev/null \
  | openssl x509 -text -noout
```

---

## kubectl Cert Commands Cheat Sheet

```bash
# ===== cert-manager =====
kubectl get certificate -A                               # All certs
kubectl get clusterissuer                                # All ClusterIssuers
kubectl get issuer -A                                    # All Issuers
kubectl describe certificate <name> -n <ns>              # Cert details + events
kubectl get certificaterequest -A                        # CSR status
kubectl get order -A                                     # ACME orders
kubectl get challenge -A                                 # ACME challenges
kubectl logs -l app=cert-manager -n cert-manager         # cert-manager logs

# ===== Dapr mTLS =====
dapr mtls -k                                             # Check mTLS status
dapr mtls export -o ./certs                              # Export root cert
kubectl get secret dapr-trust-bundle -n dapr-system      # Dapr trust bundle
kubectl logs -l app=dapr-sentry -n dapr-system           # Sentry logs
kubectl logs <pod> -c daprd                              # Sidecar logs

# ===== CoreDNS =====
kubectl get pods -n kube-system -l k8s-app=kube-dns      # CoreDNS pods
kubectl logs -l k8s-app=kube-dns -n kube-system          # CoreDNS logs
kubectl get configmap coredns -n kube-system -o yaml     # CoreDNS config

# ===== Inspect secrets =====
kubectl get secret <name> -n <ns> -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -text -noout               # View cert from secret

# ===== DNS testing =====
kubectl run dns-test --image=busybox:1.36 --rm -it -- \
  nslookup <service>.<namespace>.svc.cluster.local       # Test DNS resolution
```

---

## .NET mTLS Code Cheat Sheet

```csharp
// ===== LOADING CERTS =====
// From PFX
var cert = new X509Certificate2("cert.pfx", "password");

// From PEM (.NET 8+)
var cert = X509Certificate2.CreateFromPemFile("cert.pem", "key.pem");

// ===== READING METADATA =====
cert.Subject          // "CN=device-042, OU=IoT-Sensors, O=Acme Corp"
cert.Issuer           // "CN=Root CA, O=Acme Corp"
cert.Thumbprint       // "A1B2C3D4..."
cert.SerialNumber     // "0A1B2C..."
cert.NotBefore        // DateTime
cert.NotAfter         // DateTime
cert.HasPrivateKey    // bool

// ===== KESTREL mTLS SERVER =====
builder.WebHost.ConfigureKestrel(opt =>
    opt.ListenAnyIP(5001, lo =>
        lo.UseHttps(https => {
            https.ServerCertificate = serverCert;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        })));

// ===== HTTPCLIENT mTLS CLIENT =====
var handler = new HttpClientHandler();
handler.ClientCertificates.Add(clientCert);
var client = new HttpClient(handler);

// ===== READ CLIENT CERT IN ENDPOINT =====
app.MapGet("/api", (HttpContext ctx) => {
    var cert = ctx.Connection.ClientCertificate;
    var deviceId = cert?.GetNameInfo(X509NameType.SimpleName, false);
    return Results.Ok(new { DeviceId = deviceId });
});

// ===== CERT AUTH MIDDLEWARE =====
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(opt => {
        opt.AllowedCertificateTypes = CertificateTypes.Chained;
        opt.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
        opt.CustomTrustStore.Add(caCert);
    });

// ===== DAPR CLIENT (no TLS code needed!) =====
builder.Services.AddDaprClient();
// ...
var result = await dapr.InvokeMethodAsync<Order, Result>(
    "target-service", "method", data);
```

---

## Glossary

| Term | Definition |
|------|-----------|
| **ACME** | Automatic Certificate Management Environment - protocol for automated cert issuance (RFC 8555) |
| **CA** | Certificate Authority - entity that signs certificates |
| **cert-manager** | Kubernetes controller that automates certificate lifecycle |
| **ClusterIssuer** | Cluster-wide cert-manager issuer (not namespace-scoped) |
| **CN** | Common Name - primary identity field in certificate Subject |
| **CoreDNS** | Kubernetes cluster DNS server |
| **CRL** | Certificate Revocation List - list of revoked cert serial numbers |
| **CSR** | Certificate Signing Request - contains public key + identity, sent to CA |
| **Dapr** | Distributed Application Runtime - sidecar-based microservice framework |
| **DER** | Distinguished Encoding Rules - binary cert format |
| **DN** | Distinguished Name - structured identity (CN, O, OU, C, etc.) |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm - modern signing algorithm |
| **EKU** | Extended Key Usage - what a cert is authorized for (serverAuth, clientAuth) |
| **FQDN** | Fully Qualified Domain Name - complete DNS name (host.ns.svc.cluster.local) |
| **HSM** | Hardware Security Module - dedicated hardware for key storage |
| **Issuer** | Namespace-scoped cert-manager issuer |
| **mTLS** | Mutual TLS - both client and server authenticate with certificates |
| **OCSP** | Online Certificate Status Protocol - real-time revocation check |
| **OID** | Object Identifier - unique number identifying a cert extension type |
| **PEM** | Privacy-Enhanced Mail - base64 cert format (BEGIN CERTIFICATE...) |
| **PFX/PKCS#12** | Binary format containing cert + private key (used by .NET/Windows) |
| **PKI** | Public Key Infrastructure - system for managing certificates and keys |
| **RSA** | Rivest-Shamir-Adleman - classic public key algorithm |
| **SAN** | Subject Alternative Name - additional identities (DNS, IP, URI, Email) |
| **Sentry** | Dapr's built-in certificate authority |
| **SNI** | Server Name Indication - TLS extension to specify hostname |
| **SPIFFE** | Secure Production Identity Framework for Everyone - workload identity standard |
| **TLS** | Transport Layer Security - encryption protocol (successor to SSL) |
| **TPM** | Trusted Platform Module - hardware for secure key generation/storage |
| **Trust Store** | Collection of trusted CA certificates |
| **X.509** | Standard format for public key certificates |

---

## Learning Path

```
Start Here                                        Advanced
==========                                        ========

01-TLS Fundamentals     -->  02-Cert Metadata  -->  03-mTLS Device-to-Service
& Let's Encrypt              Deep Dive              Authentication Patterns
(How certs work)             (What you can read)    (Architecture patterns)
                                     |
                                     v
                             04-Dapr mTLS       -->  05-.NET Integration
                             Architecture            with mTLS & Dapr
                             (How Dapr does it)      (Code examples)
                                     |
                                     v
                             06-Kubernetes       -->  07-Quick Reference
                             cert-manager             (This doc - cheat sheets)
                             & CoreDNS
                             (Infrastructure)
```

---

## Further Reading

- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [ACME Protocol RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)
- [cert-manager Documentation](https://cert-manager.io/docs/)
- [Dapr Security Concepts](https://docs.dapr.io/concepts/security-concept/)
- [Dapr mTLS](https://docs.dapr.io/operations/security/mtls/)
- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [Kubernetes TLS Secrets](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets)
- [CoreDNS Documentation](https://coredns.io/manual/toc/)
- [ASP.NET Core Certificate Authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/certauth)
- [X.509 Certificate Standard (RFC 5280)](https://datatracker.ietf.org/doc/html/rfc5280)
