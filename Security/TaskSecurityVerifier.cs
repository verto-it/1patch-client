using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;
using OnePatch.Client.Services;


namespace OnePatch.Client.Security;

/// <summary>
/// Enforces all client-side paranoia mode checks before a task is executed.
/// This is the final gate — even if the backend node or management server is
/// compromised, a forged/hidden/modified/expired task is rejected here.
/// </summary>
public sealed class TaskSecurityVerifier
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);
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

        // ── 1. Envelope-level checks (all modes) ─────────────────────────────

        if (!string.Equals(envelope.Algorithm, "ES256", StringComparison.Ordinal))
            Reject("Unsupported signature algorithm", envelope);

        if (!string.Equals(envelope.PayloadType, "task_bundle", StringComparison.Ordinal))
            Reject($"Wrong payload type '{envelope.PayloadType}' — expected 'task_bundle'", envelope);

        if (!string.Equals(envelope.TenantId, _options.TenantId, StringComparison.Ordinal))
            Reject($"TenantId mismatch: envelope={envelope.TenantId} client={_options.TenantId}", envelope);

        if (!_options.TrustedSigningPublicKeys.ContainsKey(envelope.KeyId))
            Reject($"Unknown signing key '{envelope.KeyId}'", envelope);

        if (!DateTimeOffset.TryParse(envelope.ExpiresAt, out var expiresAt) || expiresAt <= DateTimeOffset.UtcNow)
            Reject("Signed envelope has expired", envelope);

        // ── 2. Dev key rejection (strict + tinfoil) ───────────────────────────

        if (mode >= SecurityMode.Strict && _options.DevKeyIds.Contains(envelope.KeyId))
            Reject($"Dev signing key '{envelope.KeyId}' is not trusted in strict/tinfoil mode", envelope);

        // ── 3. Verify ECDSA signature ─────────────────────────────────────────

        VerifySignature(envelope);

        // ── 4. Verify payloadHash if present ─────────────────────────────────

        if (envelope.PayloadHash is not null)
        {
            var computedHash = ComputePayloadHash(envelope.Payload);
            if (!string.Equals(envelope.PayloadHash, computedHash, StringComparison.OrdinalIgnoreCase))
                Reject("Payload hash mismatch — task bundle may have been tampered with", envelope);
        }

        var bundle = envelope.Payload;

        // ── 5. Ledger entry checks (strict + tinfoil) ─────────────────────────

        if (mode >= SecurityMode.Strict)
        {
            if (bundle.LedgerEntry is null)
                Reject("No ledger entry present — task cannot be executed in strict/tinfoil mode", envelope);

            var ledger = bundle.LedgerEntry!;

            if (!string.Equals(ledger.State, "active", StringComparison.Ordinal))
                Reject($"Ledger entry state is '{ledger.State}' — only 'active' entries are executable", envelope);

            if (ledger.VisibleInDashboard != true)
                Reject("Ledger entry visibleInDashboard is not true — hidden task injection attempt", envelope);

            if (!DateTimeOffset.TryParse(ledger.ExpiresAt, out var ledgerExpiry) || ledgerExpiry <= DateTimeOffset.UtcNow)
                Reject("Ledger entry has expired", envelope);
        }

        // ── 6. Per-task checks ────────────────────────────────────────────────

        foreach (var task in bundle.Tasks)
            VerifyTask(task, bundle.LedgerEntry, mode);

        // ── 7. Tinfoil: approval count ────────────────────────────────────────

        if (mode == SecurityMode.Tinfoil && bundle.LedgerEntry is not null)
        {
            if (bundle.LedgerEntry.Approvals.Length < 2)
                Reject($"Tinfoil mode requires at least 2 approvals — got {bundle.LedgerEntry.Approvals.Length}", envelope);
        }

        return bundle;
    }

    private void VerifyTask(AgentTask task, TaskLedgerEntry? ledger, SecurityMode mode)
    {
        // ── notBefore delay (strict + tinfoil) ───────────────────────────────

        if (mode >= SecurityMode.Strict && task.NotBefore is not null)
        {
            if (DateTimeOffset.TryParse(task.NotBefore, out var notBefore) && DateTimeOffset.UtcNow < notBefore)
                Reject($"Task {task.Id} cannot be executed before {task.NotBefore}", task);
        }

        // ── taskHash integrity against ledger ────────────────────────────────

        if (mode >= SecurityMode.Strict && ledger is not null && task.TaskHash is not null)
        {
            if (!string.Equals(ledger.TaskHash, task.TaskHash, StringComparison.OrdinalIgnoreCase))
                Reject($"Task {task.Id} taskHash does not match ledger — task has been modified", task);
        }

        // ── Trusted source host (all modes for update_package) ───────────────

        if (string.Equals(task.Type, "update_package", StringComparison.Ordinal))
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

        // ── Tinfoil: reject high/critical risk without ledger confirmation ────

        if (mode == SecurityMode.Tinfoil && ledger is not null)
        {
            if (ledger.RiskScore >= 70 && ledger.Approvals.Length < 2)
                Reject($"Task {task.Id} has high risk score {ledger.RiskScore} but insufficient approvals for tinfoil mode", task);
        }

        _logger.LogDebug("Task {TaskId} passed security verification (mode={Mode})", task.Id, mode);
    }

    private void VerifySignature<T>(SignedEnvelope<T> envelope)
    {
        if (!_options.TrustedSigningPublicKeys.TryGetValue(envelope.KeyId, out var pemKey))
            Reject($"No public key for keyId '{envelope.KeyId}'", envelope);

        // Reconstruct the canonical envelope without the signature field
        var unsigned = new
        {
            algorithm   = envelope.Algorithm,
            expiresAt   = envelope.ExpiresAt,
            issuedAt    = envelope.IssuedAt,
            keyId       = envelope.KeyId,
            nonce       = envelope.Nonce,
            payload     = envelope.Payload,
            payloadHash = envelope.PayloadHash,
            payloadType = envelope.PayloadType,
            tenantId    = envelope.TenantId,
        };

        var canonicalBytes = Encoding.UTF8.GetBytes(CanonicalJson(JsonSerializer.SerializeToElement(unsigned, JsonOpts)));
        var sig = Base64UrlDecode(envelope.Signature);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pemKey!.Replace("\\n", "\n"));
        if (!ecdsa.VerifyData(canonicalBytes, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            Reject($"Invalid ECDSA signature (keyId={envelope.KeyId})", envelope);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string ComputePayloadHash<T>(T payload)
    {
        var json = JsonSerializer.Serialize(payload, JsonOpts);
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
