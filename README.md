# Certificate & mTLS Learning Guide

A comprehensive guide with **documentation + runnable code** for understanding TLS certificates,
mTLS authentication, Dapr security, .NET integration, and Kubernetes certificate infrastructure.

## Quick Start

```bash
# 1. Generate test certificates (requires openssl)
./scripts/generate-certs.sh

# 2. Start the mTLS server
cd src/MtlsServer && dotnet run

# 3. In another terminal, run the mTLS client
cd src/MtlsClient && dotnet run

# Or test with curl
curl --cacert scripts/certs/ca.crt \
     --cert scripts/certs/client.crt \
     --key scripts/certs/client.key \
     https://localhost:5001/api/device-info
```

## Project Structure

```
Certificate-mtls/
├── docs/                              # Detailed learning documentation (7 parts)
│   ├── 01-tls-fundamentals-and-letsencrypt.md
│   ├── 02-certificate-metadata-deepdive.md
│   ├── 03-mtls-device-to-service.md
│   ├── 04-dapr-mtls-architecture.md
│   ├── 05-dotnet-mtls-dapr-integration.md
│   ├── 06-kubernetes-cert-manager-coredns.md
│   └── 07-quick-reference.md
│
├── scripts/
│   ├── generate-certs.sh              # OpenSSL cert generator (bash)
│   ├── certs/                         # Generated certificates go here
│   ├── python/
│   │   ├── acme_certificate.py        # Let's Encrypt ACME flow (step-by-step)
│   │   └── requirements.txt
│   └── typescript/
│       ├── src/acme-certificate.ts    # Let's Encrypt ACME flow (TypeScript)
│       ├── package.json
│       └── tsconfig.json
│
└── src/
    ├── MtlsServer/                    # ASP.NET Core mTLS server
    │   ├── Program.cs                 # Kestrel mTLS + cert auth middleware
    │   └── MtlsServer.csproj
    ├── MtlsClient/                    # .NET HttpClient mTLS client
    │   ├── Program.cs                 # Client cert + custom trust store
    │   └── MtlsClient.csproj
    └── DaprService/                   # Dapr sidecar service (zero TLS code)
        ├── Program.cs                 # Service invocation, pub/sub, state
        ├── DaprService.csproj
        └── k8s/
            └── deployment.yaml        # K8s manifests + Dapr config + cert-manager
```

## Documentation

| # | Document | Topics Covered |
|---|----------|---------------|
| 01 | [TLS Fundamentals & Let's Encrypt](docs/01-tls-fundamentals-and-letsencrypt.md) | Asymmetric crypto, X.509 structure, chain of trust, TLS handshake, ACME protocol, certificate lifecycle |
| 02 | [Certificate Metadata Deep Dive](docs/02-certificate-metadata-deepdive.md) | Every X.509 field explained, extensions (SAN, EKU, Key Usage), SPIFFE URIs, reading certs in .NET and OpenSSL |
| 03 | [mTLS Device-to-Service Authentication](docs/03-mtls-device-to-service.md) | mTLS handshake, device provisioning patterns, architecture patterns (direct, gateway, service mesh), cert-based RBAC |
| 04 | [Dapr mTLS Architecture](docs/04-dapr-mtls-architecture.md) | Sentry CA, SPIFFE identity, workload certs, auto-rotation, access control policies, debugging |
| 05 | [.NET Integration with mTLS & Dapr](docs/05-dotnet-mtls-dapr-integration.md) | Kestrel mTLS config, HttpClient certs, cert auth middleware, Dapr SDK, complete service example |
| 06 | [Kubernetes cert-manager & CoreDNS](docs/06-kubernetes-cert-manager-coredns.md) | cert-manager, ClusterIssuer, ACME challenges, internal CA, CoreDNS, DNS-cert interaction |
| 07 | [Quick Reference & Cheat Sheets](docs/07-quick-reference.md) | Architecture diagrams, OpenSSL commands, kubectl commands, .NET code snippets, glossary |

## Code Examples

### Certificate Generation Scripts

| Script | What It Does |
|--------|-------------|
| `scripts/generate-certs.sh` | Generates CA + server + client certs using OpenSSL (bash, no dependencies) |
| `scripts/python/acme_certificate.py local` | Generates certs using Python cryptography library (with detailed explanations) |
| `scripts/python/acme_certificate.py acme --dry-run` | Walks through the entire ACME/Let's Encrypt flow step-by-step |
| `scripts/python/acme_certificate.py inspect --cert file.crt` | Reads and displays ALL metadata from any certificate |
| `scripts/typescript/src/acme-certificate.ts local` | TypeScript equivalent - generates certs with node-forge |

### .NET Projects

| Project | What It Demonstrates |
|---------|---------------------|
| `src/MtlsServer` | Kestrel mTLS server with certificate authentication, cert metadata reading, claims mapping, role-based authorization |
| `src/MtlsClient` | HttpClient configured for mTLS - loads client cert, custom trust store, calls secure endpoints |
| `src/DaprService` | Dapr sidecar service - ZERO TLS code, service invocation, pub/sub, state management, K8s manifests |

## Reading Order

```
01 TLS Fundamentals  -->  02 Cert Metadata  -->  03 mTLS Patterns
                                |
                                v
                          04 Dapr mTLS  -->  05 .NET Integration
                                |
                                v
                          06 K8s cert-manager  -->  07 Quick Reference
```

For the code: Start with `generate-certs.sh`, then `MtlsServer` + `MtlsClient`, then `DaprService`.
