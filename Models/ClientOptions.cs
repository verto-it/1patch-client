namespace OnePatch.Client.Services;

public enum SecurityMode { Normal, Strict, Tinfoil }

public sealed class ClientOptions
{
    public string TenantId { get; set; } = "default";
    public string ManagementUrl { get; set; } = "";
    public string EnrollmentToken { get; set; } = "";
    public string ClientName { get; set; } = "";
    public int HeartbeatSeconds { get; set; } = 60;
    public int InventoryMinutes { get; set; } = 30;
    public int NodeProbeTimeoutMilliseconds { get; set; } = 2000;

    /// <summary>keyId → PEM public key for signature verification.</summary>
    public Dictionary<string, string> TrustedSigningPublicKeys { get; set; } = [];
    

    /// <summary>
    /// Allowlist of trusted https:// origins for package downloads.
    /// PackageSourceUrl must start with one of these values.
    /// </summary>
    public List<string> TrustedDownloadHosts { get; set; } = [];

    /// <summary>
    /// Client security mode.
    /// Normal  - zero-trust baseline: signature/hash, pinned key, non-dev key,
    ///           signed visible active ledger, notBefore/expiresAt, trusted host,
    ///           and kill-switch polling.
    /// Strict  - reserved for future stricter tenant-side posture.
    /// Tinfoil - + min 2 approvals + no high/critical risk without 2 approvals.
    /// </summary>
    public SecurityMode SecurityMode { get; set; } = SecurityMode.Normal;

    /// <summary>
    /// Key IDs that are known to be dev-only.
    /// Tasks signed with these keys are rejected in every mode.
    /// </summary>
    public List<string> DevKeyIds { get; set; } = [];

    /// <summary>
    /// Break-glass key ID allowed to sign recovery tasks when kill switch is active.
    /// Only honoured in Tinfoil mode with a matching signed recovery_task envelope.
    /// </summary>
    public string? BreakGlassKeyId { get; set; }
}
