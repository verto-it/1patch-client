using System.Net.Http.Json;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;

namespace OnePatch.Client.Services;

public sealed class BackendNodeClient
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);
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
                deviceId       = _identity.DeviceId,
                tenantId       = _options.TenantId,
                hostname,
                os             = RuntimeInformation.OSDescription,
                publicKey      = _identity.PublicKey,
                enrollmentToken = _options.EnrollmentToken,
            }, cancellationToken);

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
        }
        else
        {
            _logger.LogDebug("Heartbeat acknowledged by node {NodeId}", node.Id);
        }
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

    /// <summary>
    /// Returns raw signed task bundle envelopes so the <c>TaskSecurityVerifier</c>
    /// can inspect and verify them before any task fields are unwrapped.
    /// The Worker calls this instead of the old GetTasksAsync.
    /// </summary>
    public async Task<IReadOnlyList<SignedEnvelope<TaskBundle>>> GetTaskEnvelopesAsync(CancellationToken cancellationToken)
    {
        var node = await RequireNodeAsync(cancellationToken);
        _logger.LogDebug("Polling task envelopes from node {NodeId} for device {DeviceId}", node.Id, _identity.DeviceId);

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

        if (!doc.RootElement.TryGetProperty("tasks", out var taskArray) ||
            taskArray.ValueKind != JsonValueKind.Array)
            return [];

        var envelopes = new List<SignedEnvelope<TaskBundle>>();
        foreach (var element in taskArray.EnumerateArray())
        {
            SignedEnvelope<TaskBundle>? envelope = null;
            try
            {
                // Deserialise the raw envelope — the security verifier will check the signature
                envelope = JsonSerializer.Deserialize<SignedEnvelope<TaskBundle>>(element.GetRawText(), JsonOpts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to deserialise task envelope from node {NodeId} — skipping", node.Id);
            }

            if (envelope is not null &&
                // Pre-filter: only accept task_bundle payloads for this device's tenant
                string.Equals(envelope.PayloadType, "task_bundle", StringComparison.Ordinal) &&
                string.Equals(envelope.TenantId, _options.TenantId, StringComparison.Ordinal))
            {
                envelopes.Add(envelope);
            }
            else if (envelope is not null)
            {
                _logger.LogWarning("Discarding envelope with unexpected payloadType={Type} tenantId={Tenant}",
                    envelope.PayloadType, envelope.TenantId);
            }
        }

        _logger.LogDebug("Received {Count} task envelope(s) from node {NodeId}", envelopes.Count, node.Id);
        return envelopes;
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
