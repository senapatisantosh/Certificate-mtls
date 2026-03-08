# 02 - Certificate Metadata - Diagrams

## 2.1 X.509 v3 Certificate Structure (Complete)

```mermaid
flowchart TD
    CERT["📜 X.509 v3 Certificate"]

    CERT --> TBS["TBSCertificate<br/>(To Be Signed)"]
    CERT --> SIGALG["Signature Algorithm<br/>sha256WithRSAEncryption<br/>ecdsa-with-SHA256"]
    CERT --> SIGVAL["Signature Value<br/>a3:b4:c5:d6:...<br/>(CA's signature over TBS)"]

    TBS --> VER["Version: 3"]
    TBS --> SERIAL["Serial Number<br/>04:E3:A2:1B:...<br/>(unique per CA)"]
    TBS --> ISSUER["Issuer DN<br/>C=US, O=Let's Encrypt, CN=R3"]
    TBS --> VALID["Validity<br/>Not Before: 2025-01-15<br/>Not After: 2025-04-15"]
    TBS --> SUBJECT["Subject DN<br/>CN=api.example.com<br/>O=Acme Corp<br/>OU=IoT Devices"]
    TBS --> PUBKEY["Subject Public Key Info<br/>Algorithm: ECDSA P-256<br/>Key: 04:A1:B2:C3:..."]
    TBS --> EXT["Extensions (v3)"]

    EXT --> SAN["Subject Alt Names<br/>DNS: api.example.com<br/>IP: 192.168.1.100<br/>URI: spiffe://..."]
    EXT --> KU["Key Usage ⚠️ CRITICAL<br/>digitalSignature ✅<br/>keyEncipherment ✅<br/>keyCertSign ❌"]
    EXT --> EKU["Extended Key Usage<br/>serverAuth (1.3.6.1.5.5.7.3.1)<br/>clientAuth (1.3.6.1.5.5.7.3.2)"]
    EXT --> BC["Basic Constraints ⚠️ CRITICAL<br/>CA: FALSE<br/>pathLenConstraint: N/A"]
    EXT --> AKI["Authority Key ID<br/>14:2E:B3:...<br/>(links to issuer's SKI)"]
    EXT --> SKI["Subject Key ID<br/>7A:3B:1C:...<br/>(hash of this cert's pubkey)"]
    EXT --> CRL_OCSP["CRL Distribution Points<br/>+ OCSP Responder URL"]
    EXT --> CUSTOM["Custom Extensions<br/>(OID-based metadata)"]

    style CERT fill:#4c6ef5,color:#fff
    style TBS fill:#748ffc,color:#fff
    style EXT fill:#be4bdb,color:#fff
    style SAN fill:#51cf66,color:#fff
    style EKU fill:#51cf66,color:#fff
    style KU fill:#f59f00,color:#000
    style BC fill:#f59f00,color:#000
```

## 2.2 Subject Distinguished Name (DN) Fields

```mermaid
flowchart LR
    subgraph DN["Subject Distinguished Name"]
        CN["CN = Common Name<br/>'device-042'<br/>Primary identity"]
        O["O = Organization<br/>'Acme Corp'<br/>Company name"]
        OU["OU = Org Unit<br/>'IoT-Sensors'<br/>Department / Fleet"]
        C["C = Country<br/>'US'"]
        ST["ST = State<br/>'California'"]
        L["L = Locality<br/>'San Francisco'"]
        SN["SERIALNUMBER<br/>'SN-2025-001'<br/>Device serial"]
    end

    CN --> USE_CN["Use for:<br/>Device ID<br/>Service name"]
    OU --> USE_OU["Use for:<br/>Role mapping<br/>Fleet routing<br/>RBAC"]
    O --> USE_O["Use for:<br/>Org verification<br/>Multi-tenancy"]
    SN --> USE_SN["Use for:<br/>Device registry lookup<br/>Audit trail"]

    style CN fill:#4c6ef5,color:#fff
    style OU fill:#be4bdb,color:#fff
    style O fill:#51cf66,color:#fff
    style SN fill:#f59f00,color:#000
```

## 2.3 Subject Alternative Name (SAN) Types

```mermaid
flowchart TD
    SAN["Subject Alternative Name<br/>(OID: 2.5.29.17)"]

    SAN --> DNS_SAN["type=2: DNS Name<br/>api.example.com<br/>*.example.com (wildcard)"]
    SAN --> IP_SAN["type=7: IP Address<br/>192.168.1.100<br/>10.0.0.1"]
    SAN --> URI_SAN["type=6: URI<br/>spiffe://cluster.local/<br/>ns/default/sa/myapp"]
    SAN --> EMAIL_SAN["type=1: Email (rfc822)<br/>device@example.com"]
    SAN --> DIR_SAN["type=4: Directory Name<br/>CN=device-123,O=fleet-a"]

    DNS_SAN --> USE_DNS["Used by:<br/>TLS hostname verification<br/>Browser URL matching"]
    URI_SAN --> USE_URI["Used by:<br/>Dapr SPIFFE identity<br/>Istio workload ID<br/>Service mesh identity"]
    IP_SAN --> USE_IP["Used by:<br/>Direct IP connections<br/>Internal services"]

    style SAN fill:#4c6ef5,color:#fff
    style URI_SAN fill:#be4bdb,color:#fff,stroke:#be4bdb,stroke-width:3px
```

## 2.4 Extended Key Usage - What Each OID Means

```mermaid
flowchart TD
    EKU["Extended Key Usage<br/>(OID: 2.5.29.37)"]

    EKU --> SA["serverAuth<br/>1.3.6.1.5.5.7.3.1"]
    EKU --> CA_EKU["clientAuth<br/>1.3.6.1.5.5.7.3.2"]
    EKU --> CS["codeSigning<br/>1.3.6.1.5.5.7.3.3"]
    EKU --> EP["emailProtection<br/>1.3.6.1.5.5.7.3.4"]

    SA --> SA_USE["TLS Server<br/>Certificate<br/>─────────<br/>Web servers<br/>API servers"]
    CA_EKU --> CA_USE["TLS Client<br/>Certificate<br/>─────────<br/>mTLS device auth<br/>Service-to-service"]
    CS --> CS_USE["Code Signing<br/>─────────<br/>Software packages<br/>Docker images"]
    EP --> EP_USE["Email<br/>─────────<br/>S/MIME"]

    subgraph mTLS_NOTE["For mTLS certificates"]
        BOTH["✅ BOTH serverAuth<br/>AND clientAuth needed<br/>if a service acts as<br/>both client AND server"]
    end

    SA --> BOTH
    CA_EKU --> BOTH

    style EKU fill:#4c6ef5,color:#fff
    style CA_EKU fill:#be4bdb,color:#fff
    style BOTH fill:#51cf66,color:#fff
```

## 2.5 Decision Making from Certificate Metadata

```mermaid
flowchart TD
    CONN["📡 Incoming mTLS Connection"]
    CONN --> READ["Read Client Certificate"]

    READ --> CHECK_CHAIN{"1. Chain valid?<br/>Signed by trusted CA?"}
    CHECK_CHAIN -->|No| REJECT1["❌ 403 - Untrusted CA"]
    CHECK_CHAIN -->|Yes| CHECK_EXPIRY

    CHECK_EXPIRY{"2. Cert expired?<br/>NotAfter < now?"}
    CHECK_EXPIRY -->|Yes| REJECT2["❌ 403 - Expired"]
    CHECK_EXPIRY -->|No| CHECK_EKU

    CHECK_EKU{"3. Has clientAuth EKU?"}
    CHECK_EKU -->|No| REJECT3["❌ 403 - Not a client cert"]
    CHECK_EKU -->|Yes| CHECK_CA

    CHECK_CA{"4. Is CA cert?<br/>BasicConstraints.CA?"}
    CHECK_CA -->|Yes| REJECT4["❌ 403 - CA certs not allowed"]
    CHECK_CA -->|No| READ_META

    READ_META["5. Read Metadata"]
    READ_META --> META_CN["CN → Device ID"]
    READ_META --> META_OU["OU → Fleet/Role"]
    READ_META --> META_O["O → Organization"]
    READ_META --> META_SAN["SAN URI → SPIFFE ID"]
    READ_META --> META_THUMB["Thumbprint → Pinning"]

    META_OU --> RBAC{"6. Role-Based<br/>Access Control"}

    RBAC -->|"OU=IoT-Sensors"| SENSOR["Role: sensor<br/>✅ POST /telemetry<br/>❌ POST /commands<br/>❌ GET /admin"]
    RBAC -->|"OU=IoT-Actuators"| ACTUATOR["Role: actuator<br/>✅ POST /telemetry<br/>✅ POST /commands<br/>❌ GET /admin"]
    RBAC -->|"OU=IoT-Admin"| ADMIN["Role: admin<br/>✅ POST /telemetry<br/>✅ POST /commands<br/>✅ GET /admin"]
    RBAC -->|"OU=unknown"| REJECT5["❌ 403 - Unknown role"]

    style CONN fill:#4c6ef5,color:#fff
    style REJECT1 fill:#ff6b6b,color:#fff
    style REJECT2 fill:#ff6b6b,color:#fff
    style REJECT3 fill:#ff6b6b,color:#fff
    style REJECT4 fill:#ff6b6b,color:#fff
    style REJECT5 fill:#ff6b6b,color:#fff
    style SENSOR fill:#51cf66,color:#fff
    style ACTUATOR fill:#be4bdb,color:#fff
    style ADMIN fill:#f59f00,color:#000
```

## 2.6 Certificate Encoding Formats

```mermaid
flowchart TD
    subgraph PEM["PEM (.pem, .crt, .cer)"]
        PEM_DESC["Base64 encoded<br/>Human readable<br/>-----BEGIN CERTIFICATE-----<br/>MIIFjTCCA3Wg...<br/>-----END CERTIFICATE-----"]
        PEM_USE["Used by: Linux, nginx,<br/>Apache, Go, Node.js,<br/>Kubernetes Secrets"]
    end

    subgraph DER["DER (.der, .cer)"]
        DER_DESC["Binary encoded<br/>NOT human readable<br/>Raw ASN.1 bytes"]
        DER_USE["Used by: Java,<br/>some Windows tools"]
    end

    subgraph PFX["PFX/PKCS#12 (.pfx, .p12)"]
        PFX_DESC["Binary container<br/>Contains: cert + private key + chain<br/>Password protected"]
        PFX_USE["Used by: .NET,<br/>Windows, IIS,<br/>Azure"]
    end

    PEM -->|"openssl pkcs12 -export"| PFX
    PFX -->|"openssl pkcs12 -nodes"| PEM
    PEM -->|"openssl x509 -outform DER"| DER
    DER -->|"openssl x509 -inform DER -outform PEM"| PEM

    style PEM fill:#4c6ef5,color:#fff
    style DER fill:#f59f00,color:#000
    style PFX fill:#be4bdb,color:#fff
```

## 2.7 Certificate Fields → .NET X509Certificate2 Property Map

```mermaid
flowchart LR
    subgraph CertFields["X.509 Certificate Fields"]
        F1["Subject"]
        F2["Issuer"]
        F3["Serial Number"]
        F4["Thumbprint"]
        F5["Not Before / After"]
        F6["Extensions"]
        F7["Public Key"]
        F8["Signature Algorithm"]
    end

    subgraph DotNet["X509Certificate2 in .NET"]
        P1[".Subject<br/>.SubjectName"]
        P2[".Issuer<br/>.IssuerName"]
        P3[".SerialNumber"]
        P4[".Thumbprint"]
        P5[".NotBefore<br/>.NotAfter"]
        P6[".Extensions"]
        P7[".PublicKey<br/>.GetRSAPublicKey()<br/>.GetECDsaPublicKey()"]
        P8[".SignatureAlgorithm"]
    end

    F1 --> P1
    F2 --> P2
    F3 --> P3
    F4 --> P4
    F5 --> P5
    F6 --> P6
    F7 --> P7
    F8 --> P8

    P6 --> EXT1["X509SubjectAlternativeNameExtension"]
    P6 --> EXT2["X509EnhancedKeyUsageExtension"]
    P6 --> EXT3["X509KeyUsageExtension"]
    P6 --> EXT4["X509BasicConstraintsExtension"]

    style CertFields fill:#4c6ef5,color:#fff
    style DotNet fill:#be4bdb,color:#fff
```
