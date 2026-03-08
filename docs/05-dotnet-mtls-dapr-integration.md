# 05 - .NET Integration with mTLS and Dapr

## Table of Contents
- [.NET Certificate APIs Overview](#net-certificate-apis-overview)
- [Kestrel mTLS Server Configuration](#kestrel-mtls-server-configuration)
- [HttpClient mTLS Client Configuration](#httpclient-mtls-client-configuration)
- [Reading Client Certificate Metadata in ASP.NET Core](#reading-client-certificate-metadata-in-aspnet-core)
- [Certificate-Based Authentication Middleware](#certificate-based-authentication-middleware)
- [Dapr SDK for .NET](#dapr-sdk-for-net)
- [.NET + Dapr: Complete Service Example](#net--dapr-complete-service-example)
- [Certificate Management in .NET](#certificate-management-in-net)
- [Testing mTLS Locally](#testing-mtls-locally)

---

## .NET Certificate APIs Overview

```
System.Security.Cryptography.X509Certificates
==============================================

Key Classes:
+----------------------------+------------------------------------------+
| Class                      | Purpose                                  |
+----------------------------+------------------------------------------+
| X509Certificate2           | Load, read, and use certificates         |
| X509Chain                  | Build and validate cert chains           |
| X509Store                  | Access Windows/system cert store         |
| X500DistinguishedName      | Parse Subject/Issuer DN fields           |
| X509Extension              | Base class for cert extensions           |
| X509SubjectAlternativeNameExtension | Read SAN entries              |
| X509KeyUsageExtension      | Read Key Usage bits                      |
| X509EnhancedKeyUsageExtension | Read Extended Key Usage OIDs          |
| X509BasicConstraintsExtension | Read CA flag and path length          |
+----------------------------+------------------------------------------+

Loading a certificate:
+----------------------------+------------------------------------------+
| Source                     | Code                                     |
+----------------------------+------------------------------------------+
| PFX file                   | new X509Certificate2("cert.pfx", "pass") |
| PEM file (.NET 8+)         | X509Certificate2.CreateFromPemFile(...)   |
| PEM string (.NET 8+)       | X509Certificate2.CreateFromPem(...)       |
| Cert store                 | X509Store + Find()                       |
| Kubernetes Secret          | File.ReadAllBytes() -> new X509Cert2()   |
| Azure Key Vault            | CertificateClient.DownloadCertificate()  |
+----------------------------+------------------------------------------+
```

---

## Kestrel mTLS Server Configuration

### Approach 1: Program.cs Configuration (Recommended)

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Configure Kestrel for mTLS
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5001, listenOptions =>
    {
        listenOptions.UseHttps(httpsOptions =>
        {
            // Server certificate (what clients see)
            httpsOptions.ServerCertificate = new X509Certificate2(
                "server.pfx", "server-password"
            );

            // THIS IS THE mTLS PART:
            // Require client certificates
            httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;

            // Validate client certificates
            httpsOptions.ClientCertificateValidation = (cert, chain, errors) =>
            {
                // Option 1: Trust any cert signed by our CA (chain validation)
                if (errors == SslPolicyErrors.None)
                    return true;

                // Option 2: Custom validation
                // Check specific issuer, thumbprint, etc.
                return false;
            };
        });
    });
});

var app = builder.Build();
app.Run();
```

### Approach 2: appsettings.json Configuration

```json
{
  "Kestrel": {
    "Endpoints": {
      "HttpsWithClientCert": {
        "Url": "https://0.0.0.0:5001",
        "Certificate": {
          "Path": "server.pfx",
          "Password": "server-password"
        },
        "ClientCertificateMode": "RequireCertificate",
        "Tls": {
          "SslProtocols": ["Tls13", "Tls12"]
        }
      }
    }
  }
}
```

### ClientCertificateMode Options

```
+---------------------------+--------------------------------------------------+
| Mode                      | Behavior                                         |
+---------------------------+--------------------------------------------------+
| NoCertificate (default)   | Don't request client cert (standard TLS)         |
| DelayCertificate          | Start without cert, request later if needed      |
| AllowCertificate          | Request cert but don't require it                |
| RequireCertificate        | REQUIRE client cert (mTLS - reject if missing)   |
+---------------------------+--------------------------------------------------+
```

---

## HttpClient mTLS Client Configuration

When your .NET service needs to call another service using mTLS:

```csharp
// Create an HttpClient that presents a client certificate

var clientCert = new X509Certificate2("client.pfx", "client-password");

var handler = new HttpClientHandler();

// Add client certificate
handler.ClientCertificates.Add(clientCert);

// Configure server cert validation (optional - for custom CAs)
handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
{
    // Trust our internal CA
    if (errors == SslPolicyErrors.None)
        return true;

    // Or check specific thumbprint
    if (cert?.GetCertHashString(HashAlgorithmName.SHA256) == "EXPECTED_THUMBPRINT")
        return true;

    return false;
};

var client = new HttpClient(handler);
var response = await client.GetAsync("https://api.internal:5001/data");
```

### Using IHttpClientFactory (Production Pattern)

```csharp
// Program.cs - Register named HttpClient with mTLS
builder.Services.AddHttpClient("mTLSClient")
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var handler = new HttpClientHandler();

        // Load client cert from file or store
        var cert = new X509Certificate2("client.pfx", "password");
        handler.ClientCertificates.Add(cert);

        return handler;
    });

// In your service class
public class MyService
{
    private readonly HttpClient _client;

    public MyService(IHttpClientFactory factory)
    {
        _client = factory.CreateClient("mTLSClient");
    }

    public async Task<string> CallSecureService()
    {
        var response = await _client.GetAsync("https://secure-service:5001/api/data");
        return await response.Content.ReadAsStringAsync();
    }
}
```

---

## Reading Client Certificate Metadata in ASP.NET Core

### In a Controller / Minimal API

```csharp
// Minimal API endpoint that reads client cert
app.MapGet("/api/device-info", (HttpContext context) =>
{
    var cert = context.Connection.ClientCertificate;

    if (cert == null)
        return Results.Unauthorized();

    // Parse Subject fields
    var subject = cert.Subject;  // "CN=device-042, OU=IoT-Fleet-East, O=Acme Corp"

    // Extract individual fields
    var cn = GetSubjectField(cert.Subject, "CN");     // "device-042"
    var ou = GetSubjectField(cert.Subject, "OU");     // "IoT-Fleet-East"
    var org = GetSubjectField(cert.Subject, "O");     // "Acme Corp"

    // Read extensions
    var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
    var hasClientAuth = eku?.EnhancedKeyUsages
        .Cast<Oid>()
        .Any(o => o.Value == "1.3.6.1.5.5.7.3.2") ?? false;  // clientAuth OID

    // Read SAN
    var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
    var dnsNames = san?.EnumerateDnsNames().ToList() ?? new List<string>();

    return Results.Ok(new
    {
        DeviceId = cn,
        Fleet = ou,
        Organization = org,
        Thumbprint = cert.Thumbprint,
        SerialNumber = cert.SerialNumber,
        NotBefore = cert.NotBefore,
        NotAfter = cert.NotAfter,
        Issuer = cert.Issuer,
        HasClientAuth = hasClientAuth,
        DnsNames = dnsNames,
        Algorithm = cert.SignatureAlgorithm.FriendlyName
    });
});

// Helper to extract DN fields
static string? GetSubjectField(string subject, string field)
{
    var parts = subject.Split(',', StringSplitOptions.TrimEntries);
    var match = parts.FirstOrDefault(p => p.StartsWith($"{field}="));
    return match?.Substring(field.Length + 1);
}
```

### In a Controller

```csharp
[ApiController]
[Route("api/[controller]")]
public class DeviceController : ControllerBase
{
    [HttpPost("telemetry")]
    public IActionResult PostTelemetry([FromBody] TelemetryData data)
    {
        var cert = HttpContext.Connection.ClientCertificate;
        if (cert == null)
            return Unauthorized("Client certificate required");

        var deviceId = GetSubjectField(cert.Subject, "CN");
        var fleet = GetSubjectField(cert.Subject, "OU");

        // Use cert metadata for authorization
        if (fleet != "IoT-Sensors" && fleet != "IoT-Actuators")
            return Forbid($"Fleet '{fleet}' not authorized for telemetry");

        // Process telemetry with device context
        _logger.LogInformation(
            "Telemetry from device {DeviceId} in fleet {Fleet}",
            deviceId, fleet
        );

        return Ok();
    }
}
```

---

## Certificate-Based Authentication Middleware

ASP.NET Core has built-in certificate authentication:

```csharp
// Program.cs
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        // What types of certs to allow
        options.AllowedCertificateTypes = CertificateTypes.Chained; // or SelfSigned, All

        // Revocation check mode
        options.RevocationMode = X509RevocationMode.Online; // Check CRL/OCSP

        // Validate the cert chain
        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
        options.CustomTrustStore = new X509Certificate2Collection
        {
            new X509Certificate2("ca-root.crt")  // Only trust certs from this CA
        };

        // Custom validation events
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                // Certificate chain is already validated at this point
                // Now do application-level checks

                var cert = context.ClientCertificate;
                var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                var ou = GetSubjectField(cert.Subject, "OU");

                // Check against device registry
                // var device = await _deviceRegistry.FindByIdAsync(cn);
                // if (device == null) { context.Fail("Unknown device"); return Task.CompletedTask; }

                // Build claims from certificate metadata
                var claims = new List<Claim>
                {
                    new Claim("device-id", cn ?? "unknown"),
                    new Claim("fleet", ou ?? "unknown"),
                    new Claim("thumbprint", cert.Thumbprint),
                    new Claim("issuer", cert.Issuer),
                    new Claim("serial", cert.SerialNumber),
                    new Claim(ClaimTypes.AuthenticationMethod, "mTLS"),
                };

                // Add role claims based on OU
                var role = ou switch
                {
                    "IoT-Sensors" => "sensor",
                    "IoT-Actuators" => "actuator",
                    "IoT-Admin" => "admin",
                    _ => "unknown"
                };
                claims.Add(new Claim(ClaimTypes.Role, role));

                context.Principal = new ClaimsPrincipal(
                    new ClaimsIdentity(claims, context.Scheme.Name)
                );
                context.Success();
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                context.Fail($"Certificate validation failed: {context.Exception?.Message}");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("SensorsOnly", policy =>
        policy.RequireRole("sensor", "admin"));

    options.AddPolicy("ActuatorsOnly", policy =>
        policy.RequireRole("actuator", "admin"));

    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("admin"));
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// Use in endpoints:
app.MapPost("/api/telemetry", [Authorize(Policy = "SensorsOnly")] (TelemetryData data) =>
{
    // Only devices with OU=IoT-Sensors or OU=IoT-Admin can reach here
    return Results.Ok();
});
```

---

## Dapr SDK for .NET

When using Dapr, **you don't handle mTLS yourself**. The Dapr sidecar handles it.
Your .NET code talks to the sidecar over localhost (plaintext HTTP/gRPC).

### Install Dapr SDK

```bash
dotnet add package Dapr.AspNetCore
# or for client-only:
dotnet add package Dapr.Client
```

### Service Invocation (Calling Other Services)

```csharp
// Program.cs
builder.Services.AddDaprClient();

// In your service
public class OrderService
{
    private readonly DaprClient _dapr;

    public OrderService(DaprClient dapr)
    {
        _dapr = dapr;
    }

    public async Task<PaymentResult> ProcessPayment(Order order)
    {
        // Dapr handles: service discovery + mTLS + retries
        var result = await _dapr.InvokeMethodAsync<Order, PaymentResult>(
            appId: "payment-service",      // Target Dapr app-id
            methodName: "process",          // HTTP method on target
            data: order
        );

        return result;
    }
}
```

### Receiving Invocations (Being Called by Other Services)

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDaprClient();
builder.Services.AddControllers().AddDapr();  // Add Dapr integration

var app = builder.Build();

app.UseCloudEvents();          // For pub/sub
app.MapSubscribeHandler();     // For pub/sub

// Your endpoints are normal ASP.NET Core endpoints
// Dapr sidecar forwards incoming mTLS-authenticated requests to you
app.MapPost("/process", (Order order) =>
{
    // The caller has already been mTLS-authenticated by Dapr
    // You can focus on business logic
    return new PaymentResult { Success = true };
});

app.Run();
```

### Pub/Sub with mTLS

```csharp
// Publishing (all communication is mTLS-secured between sidecars)
await _dapr.PublishEventAsync(
    pubsubName: "rabbitmq",
    topicName: "orders",
    data: new OrderCreatedEvent { OrderId = 123 }
);

// Subscribing
[Topic("rabbitmq", "orders")]
app.MapPost("/orders", (OrderCreatedEvent evt) =>
{
    Console.WriteLine($"Received order: {evt.OrderId}");
    return Results.Ok();
});
```

### State Management

```csharp
// Save state (Dapr sidecar communicates with state store via mTLS)
await _dapr.SaveStateAsync("statestore", "order-123", order);

// Get state
var order = await _dapr.GetStateAsync<Order>("statestore", "order-123");
```

### Secrets

```csharp
// Get secrets (Dapr sidecar retrieves from secret store)
var secret = await _dapr.GetSecretAsync("kubernetes", "my-secret");
var connectionString = secret["connection-string"];
```

---

## .NET + Dapr: Complete Service Example

Here's a complete .NET 8 service with Dapr mTLS:

### Project Structure

```
OrderService/
├── OrderService.csproj
├── Program.cs
├── Models/
│   ├── Order.cs
│   └── PaymentResult.cs
├── Services/
│   └── OrderProcessor.cs
├── appsettings.json
├── Dockerfile
└── k8s/
    ├── deployment.yaml
    └── components/
        ├── statestore.yaml
        └── pubsub.yaml
```

### Program.cs

```csharp
using Dapr.Client;

var builder = WebApplication.CreateBuilder(args);

// Add Dapr
builder.Services.AddDaprClient();
builder.Services.AddControllers().AddDapr();

// Register services
builder.Services.AddScoped<OrderProcessor>();

var app = builder.Build();

app.UseCloudEvents();
app.MapSubscribeHandler();

// Health check (Dapr uses this)
app.MapGet("/health", () => Results.Ok("healthy"));

// Create order - called by other services via Dapr mTLS
app.MapPost("/orders", async (Order order, OrderProcessor processor) =>
{
    var result = await processor.ProcessAsync(order);
    return Results.Ok(result);
});

// Handle payment result - subscribed via pub/sub (mTLS between sidecars)
[Topic("pubsub", "payment-results")]
app.MapPost("/payment-result", (PaymentResult result, ILogger<Program> logger) =>
{
    logger.LogInformation("Payment {Status} for order {OrderId}",
        result.Success ? "succeeded" : "failed",
        result.OrderId);
    return Results.Ok();
});

app.Run();
```

### OrderProcessor.cs

```csharp
public class OrderProcessor
{
    private readonly DaprClient _dapr;
    private readonly ILogger<OrderProcessor> _logger;

    public OrderProcessor(DaprClient dapr, ILogger<OrderProcessor> logger)
    {
        _dapr = dapr;
        _logger = logger;
    }

    public async Task<OrderResult> ProcessAsync(Order order)
    {
        // 1. Save order state (sidecar -> state store, all mTLS)
        await _dapr.SaveStateAsync("statestore", $"order-{order.Id}", order);

        // 2. Call payment service (sidecar -> sidecar, mTLS automatic)
        var paymentResult = await _dapr.InvokeMethodAsync<Order, PaymentResult>(
            appId: "payment-service",
            methodName: "process",
            data: order
        );

        // 3. Publish event (sidecar -> message broker, mTLS if supported)
        await _dapr.PublishEventAsync("pubsub", "order-events", new
        {
            OrderId = order.Id,
            Status = paymentResult.Success ? "completed" : "failed",
            Timestamp = DateTime.UtcNow
        });

        _logger.LogInformation(
            "Order {OrderId} processed. Payment: {Status}",
            order.Id,
            paymentResult.Success ? "success" : "failed"
        );

        return new OrderResult
        {
            OrderId = order.Id,
            Success = paymentResult.Success
        };
    }
}
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: order-service
  labels:
    app: order-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: order-service
  template:
    metadata:
      labels:
        app: order-service
      annotations:
        # Dapr annotations - this is all you need for mTLS!
        dapr.io/enabled: "true"
        dapr.io/app-id: "order-service"
        dapr.io/app-port: "5000"
        dapr.io/config: "appconfig"          # References access control config
        dapr.io/log-level: "info"
        dapr.io/sidecar-cpu-request: "100m"
        dapr.io/sidecar-memory-request: "128Mi"
    spec:
      containers:
        - name: order-service
          image: myregistry/order-service:latest
          ports:
            - containerPort: 5000
          env:
            - name: ASPNETCORE_URLS
              value: "http://+:5000"    # HTTP to sidecar (localhost)
          resources:
            requests:
              cpu: "200m"
              memory: "256Mi"
```

> **Notice:** The application listens on HTTP (not HTTPS). The Dapr sidecar
> handles all mTLS. Your app talks to the sidecar over localhost HTTP.

---

## Certificate Management in .NET

### Loading Certificates from Different Sources

```csharp
// 1. From PFX file
var cert = new X509Certificate2("cert.pfx", "password",
    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

// 2. From PEM files (.NET 8+)
var cert = X509Certificate2.CreateFromPemFile("cert.pem", "key.pem");

// 3. From PEM strings (.NET 8+)
var certPem = File.ReadAllText("cert.pem");
var keyPem = File.ReadAllText("key.pem");
var cert = X509Certificate2.CreateFromPem(certPem, keyPem);

// 4. From Azure Key Vault
using Azure.Security.KeyVault.Certificates;
var client = new CertificateClient(new Uri("https://myvault.vault.azure.net/"), new DefaultAzureCredential());
var certResponse = await client.DownloadCertificateAsync("my-cert");
X509Certificate2 cert = certResponse.Value;

// 5. From Kubernetes Secret (mounted as file)
var certBytes = File.ReadAllBytes("/var/run/secrets/tls/tls.crt");
var keyBytes = File.ReadAllBytes("/var/run/secrets/tls/tls.key");
var cert = X509Certificate2.CreateFromPem(
    System.Text.Encoding.UTF8.GetString(certBytes),
    System.Text.Encoding.UTF8.GetString(keyBytes)
);

// 6. From Windows Certificate Store
using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
store.Open(OpenFlags.ReadOnly);
var cert = store.Certificates
    .Find(X509FindType.FindByThumbprint, "THUMBPRINT_HERE", validOnly: true)
    .FirstOrDefault();
```

### Certificate Chain Validation

```csharp
public static bool ValidateCertificateChain(X509Certificate2 cert, X509Certificate2 rootCa)
{
    var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(rootCa);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Or Online
    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

    bool isValid = chain.Build(cert);

    if (!isValid)
    {
        foreach (var status in chain.ChainStatus)
        {
            Console.WriteLine($"Chain error: {status.StatusInformation}");
        }
    }

    return isValid;
}
```

---

## Testing mTLS Locally

### Generate Test Certificates

```bash
#!/bin/bash
# generate-test-certs.sh

# 1. Generate Root CA
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 365 \
  -subj "/CN=Test Root CA/O=Test Org"

# 2. Generate Server Certificate
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -out server.csr \
  -subj "/CN=localhost/O=Test Org"
cat > server.ext << EOF
subjectAltName = DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
keyUsage = digitalSignature,keyEncipherment
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -extfile server.ext
openssl pkcs12 -export -out server.pfx -inkey server.key \
  -in server.crt -passout pass:server123

# 3. Generate Client Certificate (device)
openssl ecparam -genkey -name prime256v1 -out client.key
openssl req -new -key client.key -out client.csr \
  -subj "/CN=device-042/OU=IoT-Sensors/O=Test Org/serialNumber=SN-2025-042"
cat > client.ext << EOF
subjectAltName = URI:spiffe://test.local/ns/default/device-042,DNS:device-042.iot.test.local
extendedKeyUsage = clientAuth
keyUsage = digitalSignature
EOF
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365 -extfile client.ext
openssl pkcs12 -export -out client.pfx -inkey client.key \
  -in client.crt -passout pass:client123

echo "Generated: ca.crt, server.pfx, client.pfx"
```

### Test with curl

```bash
# Test mTLS connection
curl --cacert ca.crt \
     --cert client.crt \
     --key client.key \
     https://localhost:5001/api/device-info

# Test without client cert (should fail with RequireCertificate)
curl --cacert ca.crt \
     https://localhost:5001/api/device-info
# Expected: SSL handshake error
```

### Test with Dapr Locally

```bash
# Run with Dapr sidecar (self-hosted mode)
dapr run --app-id order-service \
         --app-port 5000 \
         --dapr-http-port 3500 \
         --config ./dapr-config.yaml \
         -- dotnet run

# Call the service through Dapr
curl http://localhost:3500/v1.0/invoke/order-service/method/orders \
  -H "Content-Type: application/json" \
  -d '{"id": 1, "amount": 99.99}'
```

---

## Key Takeaways

1. **Kestrel supports mTLS natively** - set `ClientCertificateMode.RequireCertificate`
2. **ASP.NET Core cert auth middleware** maps cert fields to Claims for authorization
3. **With Dapr, your app code has NO mTLS logic** - sidecar handles everything
4. **`X509Certificate2`** is your main tool for reading cert metadata in .NET
5. **.NET 8+ PEM support** simplifies loading certs from Kubernetes Secrets
6. **Use `IHttpClientFactory`** with cert handlers for production client mTLS
7. **Test locally** with self-signed certs and the script above

---

Next: [06 - Kubernetes cert-manager, ClusterIssuer, and CoreDNS](./06-kubernetes-cert-manager-coredns.md)
