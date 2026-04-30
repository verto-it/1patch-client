namespace OnePatch.Client.Models;

public sealed record BackendNode(string Id, string PublicUrl, string? Region, string? Site);
public sealed record InstalledApp(string Name, string Publisher, string Version, string? ProductCode, string? PackageId);
public sealed record AgentTask(
    string Id,
    string Type,
    string? AppName,
    string? PackageArtifactId,
    string? PackageId,
    string? ProductCode,
    string? SourceUrl,
    string? Sha256,
    string? InstallArgs,
    string? TargetVersion);
public sealed record TaskResult(string DeviceId, string TaskId, string Status, string? Output);
