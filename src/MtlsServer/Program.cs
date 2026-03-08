// =============================================================================
// mTLS Server - Complete ASP.NET Core Example
// =============================================================================
//
// This server demonstrates:
// 1. Kestrel configured for mTLS (requiring client certificates)
// 2. Certificate-based authentication middleware
// 3. Reading ALL certificate metadata (Subject, SAN, EKU, etc.)
// 4. Certificate-based authorization (role mapping from cert fields)
// 5. Custom trust store (only trust our CA, not system CAs)
//
// Architecture:
// ┌────────────────────────────────────────────────────────────────┐
// │  Device/Client                    mTLS Server (this code)     │
// │  ─────────────                    ──────────────────────      │
// │  Presents client.pfx ──────────→  Kestrel on port 5001       │
// │                                   │                           │
// │                                   ├─ TLS handshake            │
// │                                   │  ├─ Server presents cert  │
// │                                   │  ├─ Requests client cert  │
// │                                   │  └─ Validates client cert │
// │                                   │                           │
// │                                   ├─ Auth middleware           │
// │                                   │  ├─ Reads cert metadata   │
// │                                   │  ├─ Maps to Claims        │
// │                                   │  └─ Sets Identity         │
// │                                   │                           │
// │                                   └─ Authorization            │
// │                                      ├─ Policy checks         │
// │                                      └─ Endpoint access       │
// └────────────────────────────────────────────────────────────────┘
//
// Run:
//   1. Generate certs: python ../scripts/python/acme_certificate.py local -o ./certs
//   2. Start server:   dotnet run
//   3. Test:           See MtlsClient project or use curl

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

var builder = WebApplication.CreateBuilder(args);

// =============================================================================
// STEP 1: Configure Kestrel for mTLS
// =============================================================================
// This is where the TLS magic happens. Kestrel is the web server built into
// ASP.NET Core, and it natively supports mTLS.

var certsDir = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "scripts", "certs");

builder.WebHost.ConfigureKestrel(options =>
{
    // HTTPS endpoint with mTLS
    options.ListenAnyIP(5001, listenOptions =>
    {
        listenOptions.UseHttps(httpsOptions =>
        {
            // ─── Server Certificate ───
            // This is what the CLIENT sees and validates.
            // Contains: CN=localhost, SANs: localhost, 127.0.0.1
            var serverPfxPath = Path.Combine(certsDir, "server.pfx");
            if (File.Exists(serverPfxPath))
            {
                httpsOptions.ServerCertificate = new X509Certificate2(
                    serverPfxPath, "server123"
                );
                Console.WriteLine($"[Kestrel] Loaded server cert: {httpsOptions.ServerCertificate.Subject}");
            }
            else
            {
                Console.WriteLine($"[Kestrel] WARNING: Server cert not found at {serverPfxPath}");
                Console.WriteLine($"[Kestrel] Generate certs first: python scripts/python/acme_certificate.py local -o scripts/certs");
            }

            // ─── mTLS Configuration ───
            // RequireCertificate: The server will REJECT connections without a valid client cert.
            // This is the core of mTLS - both sides must present certificates.
            //
            // Options:
            //   NoCertificate       - Standard TLS (no client cert requested)
            //   AllowCertificate    - Request client cert but don't require it
            //   RequireCertificate  - REQUIRE client cert (mTLS!) ← We use this
            //   DelayCertificate    - Request cert after initial handshake
            httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;

            // ─── Client Certificate Validation ───
            // This callback runs DURING the TLS handshake, before any HTTP processing.
            // If it returns false, the connection is rejected at the TLS level.
            httpsOptions.ClientCertificateValidation = (cert, chain, sslPolicyErrors) =>
            {
                // In production, you might:
                // 1. Check against a custom CA (handled by the auth middleware below)
                // 2. Check thumbprint against an allowlist
                // 3. Check revocation status

                // For now, let the authentication middleware handle validation
                // (it has more granular control)
                return true;
            };
        });
    });

    // Also listen on HTTP for health checks (no mTLS)
    options.ListenAnyIP(5000, listenOptions =>
    {
        // Plain HTTP - for health checks, metrics, etc.
    });
});

// =============================================================================
// STEP 2: Configure Certificate Authentication
// =============================================================================
// ASP.NET Core has built-in certificate authentication middleware.
// It validates the client certificate and maps it to a ClaimsPrincipal.

builder.Services
    .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        // ─── Certificate Type ───
        // Chained: Must chain to a trusted CA (not self-signed leaf certs)
        // SelfSigned: Accept self-signed certs
        // All: Accept both
        options.AllowedCertificateTypes = CertificateTypes.Chained;

        // ─── Revocation Checking ───
        // NoCheck: Don't check CRL/OCSP (fast, for dev/internal)
        // Online: Check CRL/OCSP endpoints in cert (production)
        // Offline: Check local CRL cache only
        options.RevocationMode = X509RevocationMode.NoCheck;

        // ─── Custom Trust Store ───
        // CRITICAL: By default, .NET trusts the SYSTEM trust store (all public CAs).
        // For mTLS, you want to ONLY trust YOUR CA.
        // Otherwise, anyone with a cert from any public CA could authenticate!
        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;

        var caCertPath = Path.Combine(certsDir, "ca.crt");
        if (File.Exists(caCertPath))
        {
            options.CustomTrustStore = new X509Certificate2Collection
            {
                new X509Certificate2(caCertPath)
            };
            Console.WriteLine($"[Auth] Trusting CA: {new X509Certificate2(caCertPath).Subject}");
        }

        // ─── Validation Events ───
        // This is where you read certificate metadata and create Claims.
        options.Events = new CertificateAuthenticationEvents
        {
            // Called AFTER the certificate chain is validated
            OnCertificateValidated = context =>
            {
                var cert = context.ClientCertificate;

                Console.WriteLine("\n" + new string('─', 60));
                Console.WriteLine("CLIENT CERTIFICATE VALIDATED");
                Console.WriteLine(new string('─', 60));

                // ─── Read ALL certificate metadata ───

                // 1. Subject fields
                var subject = cert.Subject;
                var cn = GetSubjectField(subject, "CN");
                var ou = GetSubjectField(subject, "OU");
                var org = GetSubjectField(subject, "O");
                var serialNum = GetSubjectField(subject, "SERIALNUMBER");

                Console.WriteLine($"  Subject:        {subject}");
                Console.WriteLine($"  CN (Device ID): {cn}");
                Console.WriteLine($"  OU (Fleet):     {ou}");
                Console.WriteLine($"  O (Org):        {org}");
                Console.WriteLine($"  SERIALNUMBER:   {serialNum}");

                // 2. Issuer
                Console.WriteLine($"  Issuer:         {cert.Issuer}");

                // 3. Validity
                Console.WriteLine($"  Not Before:     {cert.NotBefore:u}");
                Console.WriteLine($"  Not After:      {cert.NotAfter:u}");
                Console.WriteLine($"  Days Left:      {(cert.NotAfter - DateTime.UtcNow).Days}");

                // 4. Key info
                Console.WriteLine($"  Thumbprint:     {cert.Thumbprint}");
                Console.WriteLine($"  Serial:         {cert.SerialNumber}");
                Console.WriteLine($"  Algorithm:      {cert.SignatureAlgorithm.FriendlyName}");
                Console.WriteLine($"  Has Priv Key:   {cert.HasPrivateKey}");

                // 5. Extensions
                var sanExt = cert.Extensions
                    .OfType<X509SubjectAlternativeNameExtension>()
                    .FirstOrDefault();
                if (sanExt != null)
                {
                    Console.WriteLine("  SANs:");
                    foreach (var dns in sanExt.EnumerateDnsNames())
                        Console.WriteLine($"    DNS: {dns}");
                    // .NET 8+ has EnumerateIPAddresses() and other methods
                }

                var ekuExt = cert.Extensions
                    .OfType<X509EnhancedKeyUsageExtension>()
                    .FirstOrDefault();
                bool hasClientAuth = false;
                if (ekuExt != null)
                {
                    Console.WriteLine("  Extended Key Usage:");
                    foreach (var oid in ekuExt.EnhancedKeyUsages)
                    {
                        Console.WriteLine($"    {oid.FriendlyName} ({oid.Value})");
                        if (oid.Value == "1.3.6.1.5.5.7.3.2") // clientAuth OID
                            hasClientAuth = true;
                    }
                }

                var kuExt = cert.Extensions
                    .OfType<X509KeyUsageExtension>()
                    .FirstOrDefault();
                if (kuExt != null)
                {
                    Console.WriteLine($"  Key Usage:      {kuExt.KeyUsages}");
                }

                var bcExt = cert.Extensions
                    .OfType<X509BasicConstraintsExtension>()
                    .FirstOrDefault();
                if (bcExt != null)
                {
                    Console.WriteLine($"  Is CA:          {bcExt.CertificateAuthority}");
                }

                Console.WriteLine(new string('─', 60));

                // ─── Security Checks ───

                // Check 1: Must have clientAuth EKU
                if (!hasClientAuth)
                {
                    Console.WriteLine("  ✗ REJECTED: Missing clientAuth EKU");
                    context.Fail("Certificate does not have clientAuth Extended Key Usage");
                    return Task.CompletedTask;
                }

                // Check 2: Must not be a CA cert
                if (bcExt?.CertificateAuthority == true)
                {
                    Console.WriteLine("  ✗ REJECTED: CA certificates cannot authenticate as devices");
                    context.Fail("CA certificates are not allowed for client authentication");
                    return Task.CompletedTask;
                }

                // ─── Build Claims from Certificate ───
                // Claims are the ASP.NET Core way of representing identity attributes.
                // Controllers and endpoints use these for authorization decisions.

                var claims = new List<Claim>
                {
                    // Device identity
                    new("device-id", cn ?? "unknown"),
                    new("device-fleet", ou ?? "unknown"),
                    new("device-org", org ?? "unknown"),
                    new("device-serial", serialNum ?? "unknown"),

                    // Certificate metadata
                    new("cert-thumbprint", cert.Thumbprint),
                    new("cert-serial", cert.SerialNumber),
                    new("cert-issuer", cert.Issuer),
                    new("cert-not-after", cert.NotAfter.ToString("o")),
                    new(ClaimTypes.AuthenticationMethod, "mTLS"),

                    // Standard claims
                    new(ClaimTypes.Name, cn ?? "unknown"),
                    new(ClaimTypes.NameIdentifier, cert.Thumbprint),
                };

                // ─── Role Mapping from Certificate OU ───
                // This is certificate-based RBAC!
                var role = ou switch
                {
                    "IoT-Sensors" => "sensor",
                    "IoT-Actuators" => "actuator",
                    "IoT-Admin" => "admin",
                    "Backend-Services" => "service",
                    _ => "unknown"
                };
                claims.Add(new Claim(ClaimTypes.Role, role));

                Console.WriteLine($"  ✓ AUTHENTICATED as {cn} with role '{role}'");

                // Set the principal
                context.Principal = new ClaimsPrincipal(
                    new ClaimsIdentity(claims, context.Scheme.Name)
                );
                context.Success();
                return Task.CompletedTask;
            },

            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"\n  ✗ AUTH FAILED: {context.Exception?.Message}");
                return Task.CompletedTask;
            }
        };
    });

// =============================================================================
// STEP 3: Configure Authorization Policies
// =============================================================================
// Define what each role can access.

builder.Services.AddAuthorization(options =>
{
    // Policy: Only sensors and admins
    options.AddPolicy("SensorsAllowed", policy =>
        policy.RequireRole("sensor", "admin"));

    // Policy: Only actuators and admins
    options.AddPolicy("ActuatorsAllowed", policy =>
        policy.RequireRole("actuator", "admin"));

    // Policy: Admin only
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("admin"));

    // Policy: Any authenticated device
    options.AddPolicy("AnyDevice", policy =>
        policy.RequireAuthenticatedUser());

    // Policy: Custom - check specific cert fields
    options.AddPolicy("ProductionDevicesOnly", policy =>
        policy.RequireAssertion(context =>
        {
            var org = context.User.FindFirst("device-org")?.Value;
            var fleet = context.User.FindFirst("device-fleet")?.Value;
            return org == "Acme Corp" && fleet?.StartsWith("IoT-") == true;
        }));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// =============================================================================
// STEP 4: Define API Endpoints
// =============================================================================

// ─── Health check (no auth, HTTP) ───
app.MapGet("/health", () => Results.Ok(new { Status = "healthy", Timestamp = DateTime.UtcNow }));

// ─── Device info (shows all cert metadata) ───
app.MapGet("/api/device-info", (HttpContext ctx) =>
{
    var cert = ctx.Connection.ClientCertificate;
    if (cert == null) return Results.Unauthorized();

    var user = ctx.User;

    return Results.Ok(new
    {
        // From Claims (populated by cert auth middleware)
        DeviceId = user.FindFirst("device-id")?.Value,
        Fleet = user.FindFirst("device-fleet")?.Value,
        Organization = user.FindFirst("device-org")?.Value,
        DeviceSerial = user.FindFirst("device-serial")?.Value,
        Role = user.FindFirst(ClaimTypes.Role)?.Value,
        AuthMethod = user.FindFirst(ClaimTypes.AuthenticationMethod)?.Value,

        // Direct from certificate
        CertificateDetails = new
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            DaysUntilExpiry = (cert.NotAfter - DateTime.UtcNow).Days,
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName,
            Version = cert.Version,

            // SAN entries
            SubjectAlternativeNames = cert.Extensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .SelectMany(san => san.EnumerateDnsNames().Select(d => $"DNS:{d}"))
                .ToList(),

            // EKU entries
            ExtendedKeyUsage = cert.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .SelectMany(eku => eku.EnhancedKeyUsages.Cast<Oid>()
                    .Select(o => $"{o.FriendlyName} ({o.Value})"))
                .ToList(),

            // Key Usage
            KeyUsage = cert.Extensions
                .OfType<X509KeyUsageExtension>()
                .Select(ku => ku.KeyUsages.ToString())
                .FirstOrDefault(),

            // Is CA?
            IsCA = cert.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .Select(bc => bc.CertificateAuthority)
                .FirstOrDefault(),

            // All extensions
            AllExtensions = cert.Extensions
                .Select(ext => new
                {
                    OID = ext.Oid?.Value,
                    Name = ext.Oid?.FriendlyName,
                    Critical = ext.Critical
                })
                .ToList()
        }
    });
}).RequireAuthorization("AnyDevice");

// ─── Telemetry endpoint (sensors + admins only) ───
app.MapPost("/api/telemetry", (HttpContext ctx, TelemetryData data) =>
{
    var deviceId = ctx.User.FindFirst("device-id")?.Value;
    var fleet = ctx.User.FindFirst("device-fleet")?.Value;

    Console.WriteLine($"[Telemetry] Device={deviceId} Fleet={fleet} Temp={data.Temperature} Humidity={data.Humidity}");

    return Results.Ok(new
    {
        Accepted = true,
        DeviceId = deviceId,
        Timestamp = DateTime.UtcNow,
        Message = $"Telemetry recorded from {deviceId} in fleet {fleet}"
    });
}).RequireAuthorization("SensorsAllowed");

// ─── Command endpoint (actuators + admins only) ───
app.MapPost("/api/commands", (HttpContext ctx, DeviceCommand command) =>
{
    var deviceId = ctx.User.FindFirst("device-id")?.Value;
    return Results.Ok(new
    {
        Executed = true,
        DeviceId = deviceId,
        Command = command.Action,
        Timestamp = DateTime.UtcNow
    });
}).RequireAuthorization("ActuatorsAllowed");

// ─── Admin endpoint ───
app.MapGet("/api/admin/status", (HttpContext ctx) =>
{
    return Results.Ok(new
    {
        ServerTime = DateTime.UtcNow,
        TotalDevices = 42,
        AdminUser = ctx.User.FindFirst("device-id")?.Value
    });
}).RequireAuthorization("AdminOnly");

// ─── Certificate chain validation endpoint (educational) ───
app.MapGet("/api/cert-chain", (HttpContext ctx) =>
{
    var cert = ctx.Connection.ClientCertificate;
    if (cert == null) return Results.Unauthorized();

    // Build the chain manually to show all certs
    using var chain = new X509Chain();
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

    var caCertPath = Path.Combine(certsDir, "ca.crt");
    if (File.Exists(caCertPath))
    {
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(new X509Certificate2(caCertPath));
    }

    var isValid = chain.Build(cert);

    return Results.Ok(new
    {
        IsValid = isValid,
        ChainElements = chain.ChainElements.Select(e => new
        {
            Subject = e.Certificate.Subject,
            Issuer = e.Certificate.Issuer,
            Thumbprint = e.Certificate.Thumbprint,
            IsSelfSigned = e.Certificate.Subject == e.Certificate.Issuer,
            NotAfter = e.Certificate.NotAfter,
            Status = e.ChainElementStatus.Select(s => s.StatusInformation).ToList()
        }).ToList(),
        ChainStatus = chain.ChainStatus.Select(s => new
        {
            s.Status,
            s.StatusInformation
        }).ToList()
    });
}).RequireAuthorization("AnyDevice");

Console.WriteLine("\n╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  mTLS Server Starting                                    ║");
Console.WriteLine("║  HTTP  (no auth):  http://localhost:5000                  ║");
Console.WriteLine("║  HTTPS (mTLS):     https://localhost:5001                 ║");
Console.WriteLine("║                                                           ║");
Console.WriteLine("║  Endpoints:                                               ║");
Console.WriteLine("║    GET  /health           - Health check (no auth)        ║");
Console.WriteLine("║    GET  /api/device-info  - Show cert metadata            ║");
Console.WriteLine("║    POST /api/telemetry    - Submit telemetry (sensors)    ║");
Console.WriteLine("║    POST /api/commands     - Send commands (actuators)     ║");
Console.WriteLine("║    GET  /api/admin/status - Admin dashboard               ║");
Console.WriteLine("║    GET  /api/cert-chain   - Show chain validation         ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝\n");

app.Run();

// =============================================================================
// Helper Method
// =============================================================================
static string? GetSubjectField(string subject, string field)
{
    var parts = subject.Split(',', StringSplitOptions.TrimEntries);
    var match = parts.FirstOrDefault(p => p.StartsWith($"{field}=", StringComparison.OrdinalIgnoreCase));
    return match?.Substring(field.Length + 1);
}

// =============================================================================
// Request Models
// =============================================================================
record TelemetryData(double Temperature, double Humidity, string? Unit = "celsius");
record DeviceCommand(string Action, Dictionary<string, string>? Parameters = null);
