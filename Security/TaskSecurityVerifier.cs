using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;
using OnePatch.Client.Services;

namespace OnePatch.Client.Security;

/// <summary>
/// Enforces all client-side security checks before a task is executed.
/// This is the final gate - even if the backend node or management server is
/// compromised, a forged/hidden/modified/expired task is rejected here.
///
/// Zero-trust guarantees enforced in ALL security modes:
///   - Valid ES256 signature from a pinned trusted key
///   - Envelope not expired, correct payloadType and tenantId
///   - Signed ledger entry present, state=active, visibleInDashboard=true, not expired
///   - notBefore not in the future
///   - taskHash matches ledger
///   - HTTPS-only download URL for update_package tasks
///
/// Additional guarantees in Tinfoil only:
///   - Minimum 2 approvals on the ledger entry
///   - High-risk tasks require minimum 2 approvals
/// </summary>
public sealed class TaskSecurityVerifier
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    // Used when building canonical JSON for signature verification.
    // TypeScript's canonicalJson() skips undefined properties; after deserialising
    // the server JSON in C# those absent fields become null. WhenWritingNull ensures
    // we exclude them too so both sides produce identical canonical bytes.
    private static readonly JsonSerializerOptions CanonicalOpts = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
    private readonly ClientOptions _options;
    private readonly ILogger<TaskSecurityVerifier> _logger;

    public TaskSecurityVerifier(IOptions<ClientOptions> options, ILogger<TaskSecurityVerifier> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Verify a signed task bundle envelope and its embedded ledger entry.
    /// Throws <see cref="TaskSecurityException"/> on any violation.
    /// </summary>
    public TaskBundle VerifyBundle(SignedEnvelope<TaskBundle> envelope)
    {
        var mode = _options.SecurityMode;

        // 1. Envelope-level checks (all modes)
        if (!string.Equals(envelope.Algorithm, "ES256", StringComparison.Ordinal))
            Reject("Unsupported signature algorithm", envelope);

        if (!string.Equals(envelope.Scope, envelope.PayloadType, StringComparison.Ordinal))
            Reject($"Scope '{envelope.Scope}' does not match payload type '{envelope.PayloadType}'", envelope);

        if (!string.Equals(envelope.PayloadType, "task_bundle", StringComparison.Ordinal))
            Reject($"Wrong payload type '{envelope.PayloadType}' - expected 'task_bundle'", envelope);

        if (!string.Equals(envelope.TenantId, _options.TenantId, StringComparison.Ordinal))
            Reject($"TenantId mismatch: envelope={envelope.TenantId} client={_options.TenantId}", envelope);

        _ = ResolveTrustedKey(envelope.KeyId, "task_bundle", envelope.TenantId);

        if (!DateTimeOffset.TryParse(envelope.ExpiresAt, out var expiresAt) || expiresAt <= DateTimeOffset.UtcNow)
            Reject("Signed envelope has expired", envelope);

        // 2. Dev key rejection (all modes)
        if (_options.DevKeyIds.Contains(envelope.KeyId))
            Reject($"Dev signing key '{envelope.KeyId}' is not trusted for executable tasks", envelope);

        // 3. Verify ECDSA signature
        VerifySignature(envelope);

        // 4. Verify payloadHash if present
        if (string.IsNullOrWhiteSpace(envelope.PayloadHash))
            Reject("Missing payloadHash - task bundle may have been tampered with", envelope);
        var computedHash = ComputePayloadHash(envelope.Payload);
        if (!string.Equals(envelope.PayloadHash, computedHash, StringComparison.OrdinalIgnoreCase))
            Reject("Payload hash mismatch - task bundle may have been tampered with", envelope);

        var bundle = envelope.Payload;

        // 5. Ledger entry checks (ALL modes)
        // A signed, visible, active, non-expired ledger entry is required in every
        // security mode. A task with no ledger, a hidden ledger, a revoked ledger,
        // or an expired ledger must never execute - regardless of client config.
        if (bundle.LedgerEntry is null)
            Reject("No ledger entry present - task cannot be executed without a signed ledger", envelope);

        var ledger = bundle.LedgerEntry!;

        if (!string.Equals(ledger.State, "active", StringComparison.Ordinal))
            Reject($"Ledger entry state is '{ledger.State}' - only 'active' entries are executable", envelope);

        if (ledger.VisibleInDashboard != true)
            Reject("Ledger entry visibleInDashboard is not true - hidden task injection attempt", envelope);

        if (!DateTimeOffset.TryParse(ledger.ExpiresAt, out var ledgerExpiry) || ledgerExpiry <= DateTimeOffset.UtcNow)
            Reject("Ledger entry has expired", envelope);

        VerifyLedgerSignature(ledger, envelope);

        // 6. Per-task checks
        foreach (var task in bundle.Tasks)
            VerifyTask(task, bundle.LedgerEntry, mode);

        // 7. Tinfoil: approval count
        if (mode == SecurityMode.Tinfoil)
        {
            if (ledger.Approvals.Length < 2)
                Reject($"Tinfoil mode requires at least 2 approvals - got {ledger.Approvals.Length}", envelope);
        }

        return bundle;
    }

    private void VerifyTask(AgentTask task, TaskLedgerEntry? ledger, SecurityMode mode)
    {
        // notBefore (ALL modes) - enforced in every mode so the mandatory review
        // delay cannot be bypassed regardless of client security configuration.
        if (task.NotBefore is not null)
        {
            if (DateTimeOffset.TryParse(task.NotBefore, out var notBefore) && DateTimeOffset.UtcNow < notBefore)
                Reject($"Task {task.Id} cannot be executed before {task.NotBefore}", task);
        }

        // taskHash integrity (ALL modes)
        if (ledger is not null && task.TaskHash is not null)
        {
            if (!string.Equals(ledger.TaskHash, task.TaskHash, StringComparison.OrdinalIgnoreCase))
                Reject($"Task {task.Id} taskHash does not match ledger - task has been modified", task);
        }

        // Trusted source host (all modes, update_package)
        if (string.Equals(task.Type, "update_package", StringComparison.Ordinal) && !IsDevelopment())
        {
            if (string.IsNullOrEmpty(task.SourceUrl) || !task.SourceUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                Reject($"Task {task.Id} has non-HTTPS source URL", task);

            if (_options.TrustedDownloadHosts.Count > 0)
            {
                var host = SafeHost(task.SourceUrl);
                if (host is null || !_options.TrustedDownloadHosts.Any(h => h.Contains(host, StringComparison.OrdinalIgnoreCase)))
                    Reject($"Task {task.Id} source host '{host}' is not in TrustedDownloadHosts", task);
            }
        }

        // Tinfoil: high risk requires 2 approvals
        if (mode == SecurityMode.Tinfoil && ledger is not null)
        {
            if (ledger.RiskScore >= 70 && ledger.Approvals.Length < 2)
                Reject($"Task {task.Id} has high risk score {ledger.RiskScore} but insufficient approvals for tinfoil mode", task);
        }

        _logger.LogDebug("Task {TaskId} passed security verification (mode={Mode})", task.Id, mode);
    }

    private void VerifySignature<T>(SignedEnvelope<T> envelope)
    {
        var keyMeta = ResolveTrustedKey(envelope.KeyId, envelope.PayloadType, envelope.TenantId);

        var unsigned = new
        {
            algorithm   = envelope.Algorithm,
            expiresAt   = envelope.ExpiresAt,
            issuedAt    = envelope.IssuedAt,
            keyId       = envelope.KeyId,
            nonce       = envelope.Nonce,
            payload     = envelope.Payload,
            payloadHash = envelope.PayloadHash,
            scope       = envelope.Scope,
            payloadType = envelope.PayloadType,
            tenantId    = envelope.TenantId,
        };

        var canonicalBytes = Encoding.UTF8.GetBytes(CanonicalJson(JsonSerializer.SerializeToElement(unsigned, CanonicalOpts)));
        var sig = Base64UrlDecode(envelope.Signature);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(keyMeta.PublicKeyPem.Replace("\\n", "\n"));
        if (!ecdsa.VerifyData(canonicalBytes, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            Reject($"Invalid ECDSA signature (keyId={envelope.KeyId})", envelope);
    }

    private void VerifyLedgerSignature(TaskLedgerEntry ledger, object context)
    {
        if (!string.Equals(ledger.Algorithm, "ES256", StringComparison.Ordinal))
            Reject("Unsupported ledger signature algorithm", context);
        if (!string.Equals(ledger.Scope, "task_ledger", StringComparison.Ordinal))
            Reject($"Wrong ledger signing scope '{ledger.Scope}'", context);
        if (string.IsNullOrWhiteSpace(ledger.PayloadHash))
            Reject("Ledger entry is missing payloadHash", context);
        if (!DateTimeOffset.TryParse(ledger.IssuedAt, out _) || string.IsNullOrWhiteSpace(ledger.Nonce))
            Reject("Ledger entry has invalid signature metadata", context);

        var payload = new
        {
            ledgerId = ledger.LedgerId,
            taskId = ledger.TaskId,
            tenantId = ledger.TenantId,
            createdBy = ledger.CreatedBy,
            createdAt = ledger.CreatedAt,
            visibleInDashboard = ledger.VisibleInDashboard,
            taskHash = ledger.TaskHash,
            riskScore = ledger.RiskScore,
            approvals = ledger.Approvals,
            notBefore = ledger.NotBefore,
            expiresAt = ledger.ExpiresAt,
        };
        var computedHash = ComputePayloadHash(payload);
        if (!string.Equals(ledger.PayloadHash, computedHash, StringComparison.OrdinalIgnoreCase))
            Reject("Ledger payload hash mismatch", context);

        var keyMeta = ResolveTrustedKey(ledger.KeyId, "task_ledger", ledger.TenantId);
        var unsigned = new
        {
            algorithm = ledger.Algorithm,
            expiresAt = ledger.ExpiresAt,
            issuedAt = ledger.IssuedAt,
            keyId = ledger.KeyId,
            nonce = ledger.Nonce,
            payload,
            payloadHash = ledger.PayloadHash,
            scope = ledger.Scope,
            payloadType = ledger.Scope,
            tenantId = ledger.TenantId,
        };
        var canonicalBytes = Encoding.UTF8.GetBytes(CanonicalJson(JsonSerializer.SerializeToElement(unsigned, CanonicalOpts)));
        var sig = Base64UrlDecode(ledger.Signature);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(keyMeta.PublicKeyPem.Replace("\\n", "\n"));
        if (!ecdsa.VerifyData(canonicalBytes, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            Reject($"Invalid ledger ECDSA signature (keyId={ledger.KeyId})", context);
    }

    private SigningKeyMetadata ResolveTrustedKey(string keyId, string expectedScope, string tenantId)
    {
        SigningKeyMetadata? meta = null;
        if (!_options.TrustedSigningKeys.TryGetValue(keyId, out meta))
        {
            if (IsDevelopment() &&
                _options.TrustedSigningKeys.Count == 0 &&
                _options.TrustedSigningPublicKeys.TryGetValue(keyId, out var legacyPem) &&
                !string.IsNullOrWhiteSpace(legacyPem))
            {
                meta = new SigningKeyMetadata { KeyId = keyId, Scope = expectedScope, Status = "active", PublicKeyPem = legacyPem, IssuedAt = DateTimeOffset.UtcNow.ToString("O"), IsDev = true, Algorithm = "ES256" };
            }
            else
            {
                Reject($"Unknown signing key '{keyId}'", new { keyId, expectedScope });
            }
        }

        if (string.Equals(meta!.Scope, "*", StringComparison.Ordinal) && !IsDevelopment())
            Reject($"Wildcard signing key '{keyId}' is not trusted", new { keyId, expectedScope });
        if (!string.Equals(meta.Scope, "*", StringComparison.Ordinal) && !string.Equals(meta.Scope, expectedScope, StringComparison.Ordinal))
            Reject($"Signing key '{keyId}' is scoped to '{meta.Scope}', not '{expectedScope}'", new { keyId, expectedScope });
        if (!string.Equals(meta.Algorithm, "ES256", StringComparison.Ordinal))
            Reject($"Unsupported signing key algorithm '{meta.Algorithm}'", new { keyId, expectedScope });
        if (string.Equals(meta.Status, "revoked", StringComparison.Ordinal))
            Reject($"Signing key '{keyId}' has been revoked", new { keyId, expectedScope });
        if (string.Equals(meta.Status, "retired", StringComparison.Ordinal))
        {
            if (!DateTimeOffset.TryParse(meta.RetirementDeadline, out var deadline) || deadline <= DateTimeOffset.UtcNow)
                Reject($"Signing key '{keyId}' retirement deadline has passed", new { keyId, expectedScope });
        }
        if (meta.IsDev && !IsDevelopment())
            Reject($"Dev signing key '{keyId}' is not trusted", new { keyId, expectedScope });
        if (meta.AllowedTenants is { Length: > 0 } && !meta.AllowedTenants.Contains(tenantId, StringComparer.Ordinal))
            Reject($"Signing key '{keyId}' is not allowed for tenant '{tenantId}'", new { keyId, expectedScope });
        return meta;
    }

    private static bool IsDevelopment()
        => string.Equals(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase);

    private static string ComputePayloadHash<T>(T payload)
    {
        var json = JsonSerializer.Serialize(payload, CanonicalOpts);
        var canonical = CanonicalJson(JsonDocument.Parse(json).RootElement);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public static string CanonicalJson(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", value.EnumerateObject()
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .Select(p => $"{JsonSerializer.Serialize(p.Name)}:{CanonicalJson(p.Value)}")) + "}",
        JsonValueKind.Array => "[" + string.Join(",", value.EnumerateArray().Select(CanonicalJson)) + "]",
        _ => value.GetRawText(),
    };

    private static string? SafeHost(string? url)
    {
        if (url is null) return null;
        try { return new Uri(url).Host.ToLowerInvariant(); } catch { return null; }
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var b64 = value.Replace('-', '+').Replace('_', '/');
        b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
        return Convert.FromBase64String(b64);
    }

    private static void Reject(string reason, object context) =>
        throw new TaskSecurityException(reason);
}

public sealed class TaskSecurityException : Exception
{
    public TaskSecurityException(string reason) : base(reason) { }
}
