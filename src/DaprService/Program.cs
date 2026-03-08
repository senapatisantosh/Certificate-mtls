// =============================================================================
// Dapr Service - mTLS is handled AUTOMATICALLY by the Dapr sidecar
// =============================================================================
//
// KEY INSIGHT: When using Dapr, your application code has ZERO TLS/mTLS logic.
// The Dapr sidecar handles:
//   - Certificate generation (via Sentry CA)
//   - mTLS between sidecars
//   - Certificate rotation (every 24 hours)
//   - Access control via SPIFFE identities
//
// Your app just talks to localhost (HTTP) → Dapr sidecar handles the rest.
//
// Architecture:
// ┌─────────────────────────────────────────────────────────────────┐
// │  Pod                                                            │
// │  ┌──────────────────┐     ┌──────────────────┐                 │
// │  │ This .NET App    │     │ Dapr Sidecar      │                 │
// │  │                  │     │ (daprd)            │                 │
// │  │ Listens on :5000 │◄───►│ Listens on :3500  │                 │
// │  │ (plain HTTP!)    │     │ (HTTP) & :50001   │                 │
// │  │                  │     │ (gRPC)             │                 │
// │  │ No TLS code!     │     │                    │                 │
// │  │ No cert loading! │     │ Has: workload cert │                 │
// │  │ No auth logic!   │     │ SPIFFE ID in SAN   │                 │
// │  │                  │     │ Auto-rotated 24h   │                 │
// │  └──────────────────┘     └────────┬───────────┘                │
// │                                     │                            │
// │                              mTLS  (automatic)                   │
// │                                     │                            │
// │                           ┌─────────▼──────────┐                │
// │                           │ Other Dapr Sidecars │                │
// │                           │ (other services)    │                │
// │                           └────────────────────┘                │
// └─────────────────────────────────────────────────────────────────┘
//
// Run (self-hosted with Dapr):
//   dapr run --app-id order-service --app-port 5000 --dapr-http-port 3500 -- dotnet run
//
// Run (Kubernetes):
//   kubectl apply -f k8s/deployment.yaml
//   (Dapr sidecar is auto-injected based on annotations)

using Dapr.Client;

var builder = WebApplication.CreateBuilder(args);

// =============================================================================
// Register Dapr Client
// =============================================================================
// The DaprClient talks to the LOCAL sidecar on localhost:3500.
// No TLS configuration needed - it's localhost communication.
builder.Services.AddDaprClient();

// Add controllers with Dapr integration (for pub/sub subscriptions)
builder.Services.AddControllers().AddDapr();

var app = builder.Build();

// CloudEvents middleware (for Dapr pub/sub)
app.UseCloudEvents();
app.MapSubscribeHandler();

// =============================================================================
// Endpoints
// =============================================================================

// ── Health check (Dapr uses this for readiness) ──
app.MapGet("/health", () => Results.Ok(new
{
    Status = "healthy",
    Service = "order-service",
    Timestamp = DateTime.UtcNow
}));

app.MapGet("/dapr/subscribe", () =>
{
    // Tell Dapr which pub/sub topics we subscribe to
    return Results.Ok(new[]
    {
        new { pubsubname = "pubsub", topic = "payment-results", route = "/payment-result" }
    });
});

// ── Create order (called by other services via Dapr) ──
// When Service B calls: POST http://localhost:3500/v1.0/invoke/order-service/method/orders
// Dapr sidecar B → (mTLS) → Dapr sidecar A → (localhost) → This endpoint
app.MapPost("/orders", async (Order order, DaprClient dapr, ILogger<Program> logger) =>
{
    logger.LogInformation("Received order {OrderId} for ${Amount}", order.Id, order.Amount);

    // ── Save state (Sidecar → State Store, mTLS if state store supports it) ──
    await dapr.SaveStateAsync("statestore", $"order-{order.Id}", order);
    logger.LogInformation("Saved order {OrderId} to state store", order.Id);

    // ── Call payment service (Sidecar → Sidecar, automatic mTLS) ──
    // Your code just specifies the app-id. Dapr resolves it and handles mTLS.
    //
    // What happens under the hood:
    // 1. Your app → HTTP POST localhost:3500/v1.0/invoke/payment-service/method/process
    // 2. Your sidecar resolves "payment-service" via Kubernetes DNS / mDNS
    // 3. Your sidecar establishes mTLS with payment-service's sidecar
    //    - Presents its workload cert (SPIFFE: spiffe://cluster.local/ns/default/order-service)
    //    - Verifies payment-service's cert (SPIFFE: spiffe://cluster.local/ns/default/payment-service)
    // 4. Payment-service's sidecar checks access control policy
    // 5. Request forwarded to payment-service app on localhost
    PaymentResult? paymentResult;
    try
    {
        paymentResult = await dapr.InvokeMethodAsync<Order, PaymentResult>(
            appId: "payment-service",       // Dapr app-id (maps to SPIFFE identity)
            methodName: "process",           // HTTP endpoint on target service
            data: order
        );
        logger.LogInformation("Payment {Status} for order {OrderId}",
            paymentResult.Success ? "succeeded" : "failed", order.Id);
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex, "Payment service unavailable, continuing without payment");
        paymentResult = new PaymentResult(order.Id, false, "Payment service unavailable");
    }

    // ── Publish event (Sidecar → Message Broker, mTLS if broker supports it) ──
    try
    {
        await dapr.PublishEventAsync("pubsub", "order-events", new
        {
            OrderId = order.Id,
            Status = paymentResult?.Success == true ? "completed" : "pending",
            Amount = order.Amount,
            Timestamp = DateTime.UtcNow
        });
        logger.LogInformation("Published order event for {OrderId}", order.Id);
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex, "Pub/sub not available, skipping event publish");
    }

    return Results.Ok(new OrderResult(
        order.Id,
        paymentResult?.Success ?? false,
        $"Order {order.Id} processed"
    ));
});

// ── Get order (state retrieval via Dapr) ──
app.MapGet("/orders/{orderId}", async (string orderId, DaprClient dapr) =>
{
    var order = await dapr.GetStateAsync<Order>("statestore", $"order-{orderId}");
    return order != null
        ? Results.Ok(order)
        : Results.NotFound(new { Message = $"Order {orderId} not found" });
});

// ── Handle payment results (pub/sub subscription) ──
// Dapr delivers messages from the "payment-results" topic to this endpoint.
// The message arrived via mTLS between the pub/sub sidecar and our sidecar.
app.MapPost("/payment-result", (PaymentResult result, ILogger<Program> logger) =>
{
    logger.LogInformation("Payment result received: Order={OrderId} Success={Success}",
        result.OrderId, result.Success);
    return Results.Ok();
});

// ── Get secrets (Dapr Secrets API) ──
app.MapGet("/config", async (DaprClient dapr, ILogger<Program> logger) =>
{
    // Dapr retrieves secrets from configured secret stores
    // (Kubernetes Secrets, Azure Key Vault, HashiCorp Vault, etc.)
    try
    {
        var secret = await dapr.GetSecretAsync("kubernetes", "app-config");
        return Results.Ok(new { SecretKeys = secret.Keys.ToList() });
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex, "Secret store not available");
        return Results.Ok(new { Message = "Secret store not configured (expected in dev)" });
    }
});

Console.WriteLine();
Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  Dapr Order Service                                      ║");
Console.WriteLine("║  App Port:   5000 (HTTP - no TLS needed!)               ║");
Console.WriteLine("║  Dapr Port:  3500 (sidecar handles mTLS)                ║");
Console.WriteLine("║                                                           ║");
Console.WriteLine("║  Endpoints:                                               ║");
Console.WriteLine("║    GET  /health              - Health check               ║");
Console.WriteLine("║    POST /orders              - Create order               ║");
Console.WriteLine("║    GET  /orders/{id}         - Get order                  ║");
Console.WriteLine("║    POST /payment-result      - Payment result (pub/sub)   ║");
Console.WriteLine("║    GET  /config              - Get secrets                ║");
Console.WriteLine("║                                                           ║");
Console.WriteLine("║  mTLS is 100% handled by Dapr sidecar - ZERO TLS code!  ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
Console.WriteLine();
Console.WriteLine("  To run with Dapr sidecar:");
Console.WriteLine("  dapr run --app-id order-service --app-port 5000 --dapr-http-port 3500 -- dotnet run");
Console.WriteLine();

app.Run();

// =============================================================================
// Models
// =============================================================================
record Order(int Id, decimal Amount, string? Customer = null, string? Product = null);
record PaymentResult(int OrderId, bool Success, string? Message = null);
record OrderResult(int OrderId, bool Success, string? Message = null);
