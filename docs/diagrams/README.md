# Mermaid Diagrams - Visual Guide to mTLS & Certificates

All diagrams use [Mermaid](https://mermaid.js.org/) syntax and render natively on GitHub,
GitLab, Azure DevOps, Notion, and most Markdown viewers.

## Diagram Index

| # | File | Diagrams Included |
|---|------|------------------|
| 01 | [TLS Fundamentals](./01-tls-fundamentals-diagrams.md) | Key pairs, chain of trust, TLS handshake sequence, ACME protocol flow, challenge types decision tree, certificate lifecycle, revocation flow, RSA vs ECDSA |
| 02 | [Certificate Metadata](./02-certificate-metadata-diagrams.md) | X.509 structure tree, Subject DN fields, SAN types, EKU OIDs, decision tree for cert-based authz, encoding formats, .NET property mapping |
| 03 | [mTLS Device-to-Service](./03-mtls-device-to-service-diagrams.md) | TLS vs mTLS comparison, full mTLS handshake sequence, factory provisioning, enrollment bootstrap, direct/gateway/mesh architectures, pinning vs chain validation |
| 04 | [Dapr mTLS](./04-dapr-mtls-diagrams.md) | Sidecar architecture, Sentry cert signing sequence, SPIFFE identity, workload cert contents, rotation timeline + Gantt, service invocation sequence, access control flowchart, trust hierarchy |
| 05 | [.NET Integration](./05-dotnet-integration-diagrams.md) | ASP.NET Core request pipeline, OU→role mapping, HttpClient mTLS sequence, Dapr SDK flow (zero TLS code), cert loading sources, complete demo architecture |
| 06 | [Kubernetes Infrastructure](./06-kubernetes-cert-manager-diagrams.md) | Certificates in K8s overview, cert-manager architecture, Issuer vs ClusterIssuer, cert lifecycle sequence, HTTP-01 challenge in K8s, internal CA bootstrap, CoreDNS architecture, DNS↔cert SAN relationship, cert-manager+Dapr integration |
| 07 | [Use Case Scenarios](./07-use-case-scenarios.md) | IoT fleet management, microservices zero-trust, certificate rotation zero-downtime, multi-environment strategy, complete external→internal request flow, device lifecycle state machine, troubleshooting decision tree |

## How to View

**GitHub / GitLab**: Diagrams render automatically in Markdown preview.

**VS Code**: Install the [Markdown Preview Mermaid Support](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) extension.

**Local CLI**: Use [mermaid-cli](https://github.com/mermaid-js/mermaid-cli) to generate PNG/SVG:
```bash
npm install -g @mermaid-js/mermaid-cli
mmdc -i diagram.md -o output.png
```

## Diagram Types Used

| Type | Purpose | Example |
|------|---------|---------|
| `sequenceDiagram` | Protocol flows, API interactions | TLS handshake, ACME flow |
| `flowchart` | Architecture, decision trees | cert-manager architecture, authz flow |
| `gantt` | Timelines | Certificate rotation schedule |
| `stateDiagram-v2` | State machines | Device lifecycle |
