// =============================================================================
// mTLS Client - Complete .NET HttpClient Example
// =============================================================================
//
// This client demonstrates:
// 1. Loading a client certificate (PFX format)
// 2. Configuring HttpClient for mTLS
// 3. Custom server certificate validation (trust our CA)
// 4. Calling the mTLS server and reading responses
// 5. Inspecting certificate metadata locally
//
// Architecture:
// ┌────────────────────────────────────────────────────────────────┐
// │  This Client                      mTLS Server                 │
// │  ───────────                      ──────────                  │
// │  1. Load client.pfx               1. Kestrel on :5001        │
// │  2. Load ca.crt (trust store)     2. Requires client cert    │
// │  3. Create HttpClient             3. Validates against CA    │
// │  4. Connect to server             4. Reads cert metadata     │
// │  5. TLS handshake:                5. Maps to Claims          │
// │     ├─ Verify server cert         6. Returns device info     │
// │     └─ Present client cert                                   │
// │  6. Send HTTP request                                        │
// │  7. Read response                                            │
// └────────────────────────────────────────────────────────────────┘
//
// Run:
//   1. Start server: cd ../MtlsServer && dotnet run
//   2. Run client:   dotnet run

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  mTLS Client - Connecting to Secure Server              ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝");

var certsDir = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "scripts", "certs");

// =============================================================================
// STEP 1: Load Client Certificate
// =============================================================================
// The client certificate is our "identity card" - we present it to the server
// during the TLS handshake to prove who we are.

Console.WriteLine("\n── Step 1: Loading Client Certificate ──");

var clientPfxPath = Path.Combine(certsDir, "client.pfx");
if (!File.Exists(clientPfxPath))
{
    Console.WriteLine($"ERROR: Client certificate not found at {clientPfxPath}");
    Console.WriteLine("Generate certs first: python scripts/python/acme_certificate.py local -o scripts/certs");
    return;
}

var clientCert = new X509Certificate2(clientPfxPath, "client123");
Console.WriteLine($"  Subject:     {clientCert.Subject}");
Console.WriteLine($"  Issuer:      {clientCert.Issuer}");
Console.WriteLine($"  Thumbprint:  {clientCert.Thumbprint}");
Console.WriteLine($"  Not After:   {clientCert.NotAfter:u}");
Console.WriteLine($"  Has Key:     {clientCert.HasPrivateKey}");

// =============================================================================
// STEP 2: Inspect Client Certificate Metadata (Educational)
// =============================================================================
// Before connecting, let's look at EVERYTHING in our certificate.

Console.WriteLine("\n── Step 2: Certificate Metadata Inspection ──");

// Parse Subject DN fields
var subject = clientCert.Subject;
Console.WriteLine($"  Full Subject:    {subject}");
Console.WriteLine($"  CN (Device ID):  {GetField(subject, "CN")}");
Console.WriteLine($"  OU (Fleet):      {GetField(subject, "OU")}");
Console.WriteLine($"  O (Org):         {GetField(subject, "O")}");
Console.WriteLine($"  SERIALNUMBER:    {GetField(subject, "SERIALNUMBER")}");

// Extensions
Console.WriteLine("\n  Extensions:");
foreach (var ext in clientCert.Extensions)
{
    var critical = ext.Critical ? " [CRITICAL]" : "";
    Console.WriteLine($"    {ext.Oid?.FriendlyName ?? ext.Oid?.Value}{critical}");

    switch (ext)
    {
        case X509SubjectAlternativeNameExtension san:
            foreach (var dns in san.EnumerateDnsNames())
                Console.WriteLine($"      DNS: {dns}");
            break;

        case X509EnhancedKeyUsageExtension eku:
            foreach (var oid in eku.EnhancedKeyUsages)
                Console.WriteLine($"      {oid.FriendlyName} ({oid.Value})");
            break;

        case X509KeyUsageExtension ku:
            Console.WriteLine($"      {ku.KeyUsages}");
            break;

        case X509BasicConstraintsExtension bc:
            Console.WriteLine($"      CA: {bc.CertificateAuthority}");
            break;
    }
}

// =============================================================================
// STEP 3: Load CA Certificate (Custom Trust Store)
// =============================================================================
// We only want to trust servers whose certificates are signed by our CA.
// If we used the system trust store, any public CA cert would be trusted.

Console.WriteLine("\n── Step 3: Loading CA Certificate (Trust Store) ──");

var caCertPath = Path.Combine(certsDir, "ca.crt");
X509Certificate2? caCert = null;
if (File.Exists(caCertPath))
{
    caCert = new X509Certificate2(caCertPath);
    Console.WriteLine($"  Trusting CA: {caCert.Subject}");
}
else
{
    Console.WriteLine("  WARNING: CA cert not found, will trust system store");
}

// =============================================================================
// STEP 4: Configure HttpClient for mTLS
// =============================================================================
// HttpClientHandler is where we configure:
// - Which client cert to present
// - How to validate the server's cert
// - TLS protocol version

Console.WriteLine("\n── Step 4: Configuring HttpClient for mTLS ──");

var handler = new HttpClientHandler();

// Add our client certificate (this is what the server sees)
handler.ClientCertificates.Add(clientCert);
Console.WriteLine("  Added client certificate to handler");

// Custom server certificate validation
// This replaces the default system trust store validation
handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslErrors) =>
{
    Console.WriteLine($"\n  [TLS] Validating server certificate:");
    Console.WriteLine($"    Server cert subject: {cert?.Subject}");
    Console.WriteLine($"    SSL errors:          {sslErrors}");

    if (cert == null) return false;

    // If no errors, the system trust store already validated it
    if (sslErrors == SslPolicyErrors.None)
    {
        Console.WriteLine("    Result: TRUSTED (system trust store)");
        return true;
    }

    // For our self-signed CA, we need custom validation
    if (caCert != null)
    {
        using var customChain = new X509Chain();
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(caCert);
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        var serverCert = new X509Certificate2(cert);
        var isValid = customChain.Build(serverCert);

        Console.WriteLine($"    Custom chain valid: {isValid}");
        if (!isValid)
        {
            foreach (var status in customChain.ChainStatus)
                Console.WriteLine($"    Chain error: {status.StatusInformation}");
        }
        else
        {
            Console.WriteLine("    Result: TRUSTED (custom CA)");
        }
        return isValid;
    }

    Console.WriteLine("    Result: REJECTED");
    return false;
};

var client = new HttpClient(handler)
{
    BaseAddress = new Uri("https://localhost:5001"),
    Timeout = TimeSpan.FromSeconds(30)
};

Console.WriteLine("  HttpClient configured and ready");

// =============================================================================
// STEP 5: Make mTLS Requests
// =============================================================================

Console.WriteLine("\n── Step 5: Making mTLS Requests ──\n");

// --- Request 1: Get device info ---
await MakeRequest("GET", "/api/device-info", null, "Device Info (shows all cert metadata)");

// --- Request 2: Post telemetry ---
var telemetry = new { Temperature = 23.5, Humidity = 65.2, Unit = "celsius" };
await MakeRequest("POST", "/api/telemetry", telemetry, "Post Telemetry (sensors only)");

// --- Request 3: Get cert chain ---
await MakeRequest("GET", "/api/cert-chain", null, "Certificate Chain Validation");

// --- Request 4: Try admin endpoint (should fail - our cert is IoT-Sensors, not admin) ---
await MakeRequest("GET", "/api/admin/status", null, "Admin Status (should be 403 for sensors)");

Console.WriteLine("\n╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  mTLS Client Complete                                    ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝");

// =============================================================================
// Helper Methods
// =============================================================================

async Task MakeRequest(string method, string path, object? body, string description)
{
    Console.WriteLine($"┌─ {description}");
    Console.WriteLine($"│  {method} {path}");

    try
    {
        HttpResponseMessage response;
        if (method == "POST" && body != null)
        {
            var json = JsonSerializer.Serialize(body);
            Console.WriteLine($"│  Body: {json}");
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            response = await client.PostAsync(path, content);
        }
        else
        {
            response = await client.GetAsync(path);
        }

        Console.WriteLine($"│  Status: {(int)response.StatusCode} {response.StatusCode}");

        var responseBody = await response.Content.ReadAsStringAsync();
        if (!string.IsNullOrEmpty(responseBody))
        {
            try
            {
                // Pretty print JSON
                var jsonDoc = JsonDocument.Parse(responseBody);
                var pretty = JsonSerializer.Serialize(jsonDoc, new JsonSerializerOptions { WriteIndented = true });
                foreach (var line in pretty.Split('\n'))
                    Console.WriteLine($"│  {line}");
            }
            catch
            {
                Console.WriteLine($"│  {responseBody}");
            }
        }
    }
    catch (HttpRequestException ex)
    {
        Console.WriteLine($"│  ERROR: {ex.Message}");
        if (ex.InnerException != null)
            Console.WriteLine($"│  Inner: {ex.InnerException.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"│  ERROR: {ex.GetType().Name}: {ex.Message}");
    }

    Console.WriteLine("└─\n");
}

static string? GetField(string dn, string field)
{
    var parts = dn.Split(',', StringSplitOptions.TrimEntries);
    var match = parts.FirstOrDefault(p => p.StartsWith($"{field}=", StringComparison.OrdinalIgnoreCase));
    return match?.Substring(field.Length + 1);
}
