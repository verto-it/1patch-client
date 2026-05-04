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
    /// Normal  – valid signature + hash + trusted host + expiry.
    /// Strict  – + notBefore delay + MFA-approved ledger + security scan pass.
    /// Tinfoil – + min 2 approvals + signed ledger + visibleInDashboard + kill-switch check + no high/critical risk.
    /// </summary>
    public SecurityMode SecurityMode { get; set; } = SecurityMode.Normal;

    /// <summary>
    /// Key IDs that are known to be dev-only.
    /// Tasks signed with these keys are rejected when SecurityMode >= Strict.
    /// </summary>
    public List<string> DevKeyIds { get; set; } = [];

    /// <summary>
    /// Break-glass key ID allowed to sign recovery tasks when kill switch is active.
    /// Only honoured in Tinfoil mode with a matching signed recovery_task envelope.
    /// </summary>
    public string? BreakGlassKeyId { get; set; }
}
