namespace OnePatch.Client.Services;

public sealed class ClientOptions
{
    public string TenantId { get; set; } = "default";
    public string ManagementUrl { get; set; } = "";
    public string EnrollmentToken { get; set; } = "";
    public string ClientName { get; set; } = "";
    public int HeartbeatSeconds { get; set; } = 60;
    public int InventoryMinutes { get; set; } = 30;
    public int NodeProbeTimeoutMilliseconds { get; set; } = 2000;

    public Dictionary<string, string> TrustedSigningPublicKeys { get; set; } = [];

    /// <summary>
    /// Allowlist of trusted https:// origins for package downloads.
    /// e.g. ["https://packages.1patch.example.com"]
    /// Package SourceUrl must start with one of these values.
    /// </summary>
    public List<string> TrustedDownloadHosts { get; set; } = [];
}
