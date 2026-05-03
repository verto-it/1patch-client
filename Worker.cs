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
        _logger.LogInformation("1Patch client starting. DeviceId={DeviceId} TenantId={TenantId} ManagementUrl={Url}",
            _identity.DeviceId, _options.TenantId, _options.ManagementUrl);

        try
        {
            await _backend.RegisterAsync(stoppingToken);
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Device registration failed — cannot continue. Check ManagementUrl and EnrollmentToken");
            throw;
        }

        var nextInventoryAt = DateTimeOffset.MinValue;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _backend.HeartbeatAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Heartbeat failed — will retry on next cycle");
            }

            try
            {
                await ExecuteTasksAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during task execution cycle");
            }

            if (DateTimeOffset.UtcNow >= nextInventoryAt)
            {
                try
                {
                    var apps = await _packages.GetInstalledAppsAsync(stoppingToken);
                    _logger.LogInformation("Inventory scan complete: {Count} installed app(s) found", apps.Count);
                    await _backend.UploadInventoryAsync(apps, stoppingToken);
                    nextInventoryAt = DateTimeOffset.UtcNow.AddMinutes(_options.InventoryMinutes);
                    _logger.LogInformation("Next inventory upload scheduled in {Minutes} minute(s)", _options.InventoryMinutes);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Inventory scan/upload failed — will retry next cycle");
                    nextInventoryAt = DateTimeOffset.UtcNow.AddMinutes(1); // short retry
                }
            }

            await Task.Delay(TimeSpan.FromSeconds(_options.HeartbeatSeconds), stoppingToken);
        }

        _logger.LogInformation("1Patch client stopping");
    }

    private async Task ExecuteTasksAsync(CancellationToken cancellationToken)
    {
        AgentTask[] tasks;
        try
        {
            tasks = await _backend.GetTasksAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to poll tasks from backend node");
            return;
        }

        if (tasks.Length == 0)
        {
            _logger.LogDebug("No pending tasks");
            return;
        }

        _logger.LogInformation("Received {Count} task(s) to process", tasks.Length);

        foreach (var task in tasks)
        {
            _logger.LogInformation("Processing task {TaskId} type={Type} app={App}", task.Id, task.Type, task.AppName);

            if (task.Type is not "update_package" and not "refresh_inventory")
            {
                _logger.LogWarning("Task {TaskId} has unknown type '{Type}' — rejecting", task.Id, task.Type);
                await _backend.ReportTaskAsync(
                    new TaskResult(_identity.DeviceId, task.Id, "rejected", "Unknown task type"),
                    cancellationToken);
                continue;
            }

            try
            {
                var output = task.Type == "refresh_inventory"
                    ? await RefreshInventoryAsync(cancellationToken)
                    : await _packages.UpdateAsync(task, cancellationToken);

                // The provider signals outcome via known prefixes — anything else means success.
                var status = output.StartsWith("Task rejected", StringComparison.OrdinalIgnoreCase) ? "rejected"
                    : output.StartsWith("Task failed", StringComparison.OrdinalIgnoreCase) ? "failed"
                    : "completed";
                _logger.LogInformation("Task {TaskId} finished with status={Status}. Output: {Output}",
                    task.Id, status, output);

                await _backend.ReportTaskAsync(
                    new TaskResult(_identity.DeviceId, task.Id, status, output),
                    cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Task {TaskId} threw an unhandled exception", task.Id);
                await _backend.ReportTaskAsync(
                    new TaskResult(_identity.DeviceId, task.Id, "failed", ex.Message),
                    cancellationToken);
            }
        }
    }

    private async Task<string> RefreshInventoryAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Refreshing inventory on demand");
        var apps = await _packages.GetInstalledAppsAsync(cancellationToken);
        await _backend.UploadInventoryAsync(apps, cancellationToken);
        _logger.LogInformation("On-demand inventory refresh complete: {Count} app(s) uploaded", apps.Count);
        return $"Uploaded {apps.Count} installed apps";
    }
}
