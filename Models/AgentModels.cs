namespace OnePatch.Client.Models;

public sealed record BackendNode(string Id, string PublicUrl, string? Region, string? Site);
public sealed record InstalledApp(string Name, string Publisher, string Version, string? ProductCode, string? PackageId);

public sealed record AgentTask(
    string Id,
    string DeviceId,
    string? TenantId,
    string Type,
    string? AppName,
    string? PackageArtifactId,
    string? PackageId,
    string? ProductCode,
    string? SourceUrl,
    string? Sha256,
    string? InstallArgs,
    string? TargetVersion,
    string? TaskHash,
    string? NotBefore,
    string? LedgerEntryId);

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
    string KeyId,
    string Signature,
    string State);

public sealed record TaskResult(string DeviceId, string TaskId, string Status, string? Output);

public sealed record SignedEnvelope<T>(
    string Algorithm,
    string KeyId,
    string PayloadType,
    string TenantId,
    string IssuedAt,
    string ExpiresAt,
    string Nonce,
    string? PayloadHash,
    T Payload,
    string Signature);

public sealed record BootstrapManifest(BackendNode[] Nodes);

public sealed record TaskBundle(AgentTask[] Tasks, TaskLedgerEntry? LedgerEntry);

public sealed record KillSwitchState(
    string Id,
    string TenantId,
    bool Active,
    string? ActivatedAt,
    string? Reason,
    string Signature,
    string KeyId);
