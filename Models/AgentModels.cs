using System.Text.Json;
using System.Text.Json.Serialization;

namespace OnePatch.Client.Models;

public sealed record BackendNode(
    string Id,
    string PublicUrl,
    string? Region,
    string? Site,
    string[]? Capabilities = null,
    string? HealthState = null,
    int TrustScore = 0,
    long? LatencyMs = null,
    int Priority = 0,
    int Weight = 0);
public sealed record InstalledApp(
    string Name,
    string Publisher,
    string Version,
    string? ProductCode,
    string? PackageId,
    string? PackageManager = null,
    string? PackageScope = null);

public sealed record AgentTask(
    string Id,
    string DeviceId,
    string? TenantId,
    string Type,
    string? AppName,
    string? PackageArtifactId,
    string? PackageId,
    string? PackageManager,
    string? PackageScope,
    string? ProductCode,
    string? SourceUrl,
    string? ManagementSourceUrl,
    string? Sha256,
    string? InstallArgs,
    string? TargetVersion,
    string? TaskHash,
    string? NotBefore,
    string? LedgerEntryId)
{
    // Captures all extra fields present in the TypeScript UpdateTask (nodeId,
    // status, createdAt, createdBy, dispatchedAt, completedAt, approvals,
    // securityScanResult, etc.) that have no C# counterpart. Without this,
    // those fields are silently dropped during deserialisation, producing
    // shorter canonical JSON than what the server originally signed, causing
    // the ECDSA verification to fail every time.
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}


public sealed record TaskApproval(
    string ApproverUserId,
    string ApprovedAt,
    string MfaChallengeId,
    string ApprovalType);

public sealed record TaskLedgerEntry(
    string LedgerId,
    string TaskId,
    string TenantId,
    string CreatedBy,
    string CreatedAt,
    bool VisibleInDashboard,
    string TaskHash,
    int RiskScore,
    TaskApproval[] Approvals,
    string NotBefore,
    string ExpiresAt,
    string Algorithm,
    string Scope,
    string IssuedAt,
    string Nonce,
    string PayloadHash,
    string KeyId,
    string Signature,
    string State)
{
    // Captures optional TypeScript fields (revokedAt, revokedReason,
    // supersededBy, …) that may be present in the signed ledger payload.
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}

public sealed record TaskResult(string DeviceId, string TaskId, string Status, string? Output);

public sealed record SignedEnvelope<T>(
    string Algorithm,
    string KeyId,
    string Scope,
    string PayloadType,
    string TenantId,
    string IssuedAt,
    string ExpiresAt,
    string Nonce,
    string PayloadHash,
    T Payload,
    string Signature);

public sealed record SigningKeyMetadata
{
    public string KeyId { get; init; } = "";
    public string Scope { get; init; } = "";
    public string Status { get; init; } = "active";
    public string PublicKeyPem { get; init; } = "";
    public string IssuedAt { get; init; } = "";
    public string? RetiredAt { get; init; }
    public string? RetirementDeadline { get; init; }
    public string? RevokedAt { get; init; }
    public bool IsDev { get; init; }
    public string Algorithm { get; init; } = "ES256";
    public string[]? AllowedTenants { get; init; }
}

public sealed record BootstrapManifest(
    BackendNode[] Nodes,
    string? TenantId = null,
    string? IssuedAt = null,
    string? PolicyId = null,
    string[]? RequiredCapabilities = null,
    string[]? Failover = null);

public sealed record TaskBundle(
    AgentTask[] Tasks,
    TaskLedgerEntry? LedgerEntry,
    JsonElement? PolicyMetadata = null,
    JsonElement? TargetScope = null,
    JsonElement? IntegrityHashes = null);

public sealed record KillSwitchState(
    string Id,
    string TenantId,
    bool Active,
    string? ActivatedAt,
    string? Reason,
    string Signature,
    string KeyId);
