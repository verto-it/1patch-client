using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;
using OnePatch.Client.Providers;
using OnePatch.Client.Services;

namespace OnePatch.Client;

public sealed class Worker : BackgroundService
{
    private readonly BackendNodeClient _backend;
    private readonly DeviceIdentityService _identity;
    private readonly IPackageProvider _packages;
    private readonly ClientOptions _options;
    private readonly ILogger<Worker> _logger;

    public Worker(
        BackendNodeClient backend,
        DeviceIdentityService identity,
        IPackageProvider packages,
        IOptions<ClientOptions> options,
        ILogger<Worker> logger)
    {
        _backend = backend;
        _identity = identity;
        _packages = packages;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("1Patch client starting");
        await _backend.RegisterAsync(stoppingToken);
        var nextInventoryAt = DateTimeOffset.MinValue;

        while (!stoppingToken.IsCancellationRequested)
        {
            await _backend.HeartbeatAsync(stoppingToken);
            await ExecuteTasksAsync(stoppingToken);

            if (DateTimeOffset.UtcNow >= nextInventoryAt)
            {
                var apps = await _packages.GetInstalledAppsAsync(stoppingToken);
                await _backend.UploadInventoryAsync(apps, stoppingToken);
                nextInventoryAt = DateTimeOffset.UtcNow.AddMinutes(_options.InventoryMinutes);
            }

            await Task.Delay(TimeSpan.FromSeconds(_options.HeartbeatSeconds), stoppingToken);
        }
    }

    private async Task ExecuteTasksAsync(CancellationToken cancellationToken)
    {
        var tasks = await _backend.GetTasksAsync(cancellationToken);
        foreach (var task in tasks)
        {
            if (task.Type is not "update_package" and not "refresh_inventory")
            {
                await _backend.ReportTaskAsync(new TaskResult(_identity.DeviceId, task.Id, "rejected", "Unknown task type"), cancellationToken);
                continue;
            }

            try
            {
                var output = task.Type == "refresh_inventory"
                    ? await RefreshInventoryAsync(cancellationToken)
                    : await _packages.UpdateAsync(task, cancellationToken);

                var status = output.Contains("rejected", StringComparison.OrdinalIgnoreCase) ? "rejected" : "completed";
                await _backend.ReportTaskAsync(new TaskResult(_identity.DeviceId, task.Id, status, output), cancellationToken);
            }
            catch (Exception ex)
            {
                await _backend.ReportTaskAsync(new TaskResult(_identity.DeviceId, task.Id, "failed", ex.Message), cancellationToken);
            }
        }
    }

    private async Task<string> RefreshInventoryAsync(CancellationToken cancellationToken)
    {
        var apps = await _packages.GetInstalledAppsAsync(cancellationToken);
        await _backend.UploadInventoryAsync(apps, cancellationToken);
        return $"Uploaded {apps.Count} installed apps";
    }
}
