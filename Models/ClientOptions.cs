namespace OnePatch.Client.Services;

public sealed class ClientOptions
{
    public string TenantId { get; set; } = "default";
    public string ManagementUrl { get; set; } = "";
    public string EnrollmentToken { get; set; } = "";
    public int HeartbeatSeconds { get; set; } = 60;
    public int InventoryMinutes { get; set; } = 30;
    public int NodeProbeTimeoutMilliseconds { get; set; } = 2000;
}
