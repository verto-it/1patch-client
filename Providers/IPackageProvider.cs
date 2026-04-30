using OnePatch.Client.Models;

namespace OnePatch.Client.Providers;

public interface IPackageProvider
{
    Task<IReadOnlyList<InstalledApp>> GetInstalledAppsAsync(CancellationToken cancellationToken);
    Task<string> UpdateAsync(AgentTask task, CancellationToken cancellationToken);
}
