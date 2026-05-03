using System.Net.Http.Json;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;

namespace OnePatch.Client.Services;

public sealed class BackendNodeClient
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly DeviceIdentityService _identity;
    private readonly NodeDiscoveryService _nodes;
    private readonly SigningVerificationService _signing;
    private readonly ClientOptions _options;
    private readonly ILogger<BackendNodeClient> _logger;

    public BackendNodeClient(
        IHttpClientFactory httpClientFactory,
        DeviceIdentityService identity,
        NodeDiscoveryService nodes,
        SigningVerificationService signing,
        IOptions<ClientOptions> options,
        ILogger<BackendNodeClient> logger)
    {
        _httpClientFactory = httpClientFactory;
        _identity = identity;
        _nodes = nodes;
        _signing = signing;
        _options = options.Value;
        _logger = logger;
    }

    public async Task RegisterAsync(CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        var hostname = string.IsNullOrWhiteSpace(_options.ClientName)
            ? Environment.MachineName
            : _options.ClientName.Trim();
        _logger.LogInformation("Registering device {DeviceId} with node {NodeId} ({Url})",
            _identity.DeviceId, node.Id, node.PublicUrl);

        var response = await _httpClientFactory.CreateClient().PostAsJsonAsync(
            $"{node.PublicUrl.TrimEnd('/')}/agent/register",
            new
            {
                deviceId = _identity.DeviceId,
                tenantId = _options.TenantId,
                hostname,
                os = RuntimeInformation.OSDescription,
                publicKey = _identity.PublicKey,
                enrollmentToken = _options.EnrollmentToken
            }, cancellationToken);

        // FIX #19: always check the response status
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogError("Registration failed: HTTP {Status} — {Body}", (int)response.StatusCode, body);
            response.EnsureSuccessStatusCode();
        }

        _logger.LogInformation("Device registration successful");
    }

    public async Task HeartbeatAsync(CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        _logger.LogDebug("Sending heartbeat to node {NodeId}", node.Id);

        var response = await _httpClientFactory.CreateClient().PostAsJsonAsync(
            $"{node.PublicUrl.TrimEnd('/')}/agent/heartbeat",
            new { deviceId = _identity.DeviceId, status = "online" },
            cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogWarning("Heartbeat rejected: HTTP {Status} — {Body}", (int)response.StatusCode, body);
            // Heartbeat failure is non-fatal — log and continue
            return;
        }

        _logger.LogDebug("Heartbeat acknowledged by node {NodeId}", node.Id);
    }

    public async Task UploadInventoryAsync(IEnumerable<InstalledApp> apps, CancellationToken cancellationToken)
    {
        var appList = apps.ToList();
        var node = await RequireNodeAsync(cancellationToken);
        _logger.LogInformation("Uploading inventory ({Count} apps) to node {NodeId}", appList.Count, node.Id);

        var response = await _httpClientFactory.CreateClient().PostAsJsonAsync(
            $"{node.PublicUrl.TrimEnd('/')}/agent/inventory",
            new { deviceId = _identity.DeviceId, apps = appList },
            cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogError("Inventory upload failed: HTTP {Status} — {Body}", (int)response.StatusCode, body);
            response.EnsureSuccessStatusCode();
        }

        _logger.LogInformation("Inventory upload successful ({Count} apps)", appList.Count);
    }

    public async Task<AgentTask[]> GetTasksAsync(CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        _logger.LogDebug("Polling tasks from node {NodeId} for device {DeviceId}", node.Id, _identity.DeviceId);

        var response = await _httpClientFactory.CreateClient().GetAsync(
            $"{node.PublicUrl.TrimEnd('/')}/agent/tasks/{_identity.DeviceId}",
            cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogWarning("Task poll failed: HTTP {Status} — {Body}", (int)response.StatusCode, body);
            return [];
        }

        var raw = await response.Content.ReadAsStringAsync(cancellationToken);
        using var doc = JsonDocument.Parse(raw);
        var envelopes = doc.RootElement.TryGetProperty("tasks", out var taskElements) && taskElements.ValueKind == JsonValueKind.Array
            ? taskElements.EnumerateArray().Select(element => element.GetRawText()).ToArray()
            : [];
        var tasks = new List<AgentTask>();
        foreach (var envelope in envelopes)
        {
            try
            {
                var bundle = _signing.VerifyJson<TaskBundle>(envelope, "task_bundle");
                tasks.AddRange(bundle.Tasks.Where(task => task.DeviceId == _identity.DeviceId));
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Rejected signed task bundle from node {NodeId}", node.Id);
            }
        }
        _logger.LogDebug("Received {Count} task(s) from node {NodeId}", tasks.Count, node.Id);
        return tasks.ToArray();
    }

    public async Task ReportTaskAsync(TaskResult result, CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        _logger.LogInformation("Reporting task {TaskId} status={Status} to node {NodeId}",
            result.TaskId, result.Status, node.Id);

        var response = await _httpClientFactory.CreateClient().PostAsJsonAsync(
            $"{node.PublicUrl.TrimEnd('/')}/agent/tasks/result",
            result,
            cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogWarning("Task result report failed: HTTP {Status} — {Body}", (int)response.StatusCode, body);
        }
        else
        {
            _logger.LogInformation("Task {TaskId} result accepted by node", result.TaskId);
        }
    }

    private async Task<BackendNode> RequireNodeAsync(CancellationToken cancellationToken)
    {
        return await _nodes.GetBestNodeAsync(cancellationToken)
            ?? throw new InvalidOperationException("No reachable 1Patch backend node found");
    }

}
