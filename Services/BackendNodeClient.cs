using System.Net.Http.Json;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;

namespace OnePatch.Client.Services;

public sealed class BackendNodeClient
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly DeviceIdentityService _identity;
    private readonly NodeDiscoveryService _nodes;
    private readonly ClientOptions _options;

    public BackendNodeClient(
        IHttpClientFactory httpClientFactory,
        DeviceIdentityService identity,
        NodeDiscoveryService nodes,
        IOptions<ClientOptions> options)
    {
        _httpClientFactory = httpClientFactory;
        _identity = identity;
        _nodes = nodes;
        _options = options.Value;
    }

    public async Task RegisterAsync(CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        var client = _httpClientFactory.CreateClient();
        await client.PostAsJsonAsync($"{node.PublicUrl.TrimEnd('/')}/agent/register", new
        {
            deviceId = _identity.DeviceId,
            tenantId = _options.TenantId,
            hostname = Environment.MachineName,
            os = RuntimeInformation.OSDescription,
            publicKey = _identity.PublicKey,
            enrollmentToken = _options.EnrollmentToken
        }, cancellationToken);
    }

    public async Task HeartbeatAsync(CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        var client = _httpClientFactory.CreateClient();
        await client.PostAsJsonAsync($"{node.PublicUrl.TrimEnd('/')}/agent/heartbeat", new
        {
            deviceId = _identity.DeviceId,
            status = "online"
        }, cancellationToken);
    }

    public async Task UploadInventoryAsync(IEnumerable<InstalledApp> apps, CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        var client = _httpClientFactory.CreateClient();
        await client.PostAsJsonAsync($"{node.PublicUrl.TrimEnd('/')}/agent/inventory", new
        {
            deviceId = _identity.DeviceId,
            apps
        }, cancellationToken);
    }

    public async Task<AgentTask[]> GetTasksAsync(CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        var client = _httpClientFactory.CreateClient();
        var result = await client.GetFromJsonAsync<TaskEnvelope>($"{node.PublicUrl.TrimEnd('/')}/agent/tasks/{_identity.DeviceId}", cancellationToken);
        return result?.Tasks ?? [];
    }

    public async Task ReportTaskAsync(TaskResult result, CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        var client = _httpClientFactory.CreateClient();
        await client.PostAsJsonAsync($"{node.PublicUrl.TrimEnd('/')}/agent/tasks/result", result, cancellationToken);
    }

    private async Task<BackendNode> RequireNodeAsync(CancellationToken cancellationToken)
    {
        return await _nodes.GetBestNodeAsync(cancellationToken) ?? throw new InvalidOperationException("No reachable 1Patch backend node found");
    }

    private sealed record TaskEnvelope(AgentTask[] Tasks);
}
