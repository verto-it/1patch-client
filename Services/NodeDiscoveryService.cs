using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;

namespace OnePatch.Client.Services;

public sealed class NodeDiscoveryService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ClientOptions _options;
    private readonly SigningVerificationService _signing;
    private readonly ILogger<NodeDiscoveryService> _logger;
    private BackendNode? _stickyNode;
    private readonly Dictionary<string, double> _latencyEwma = new(StringComparer.Ordinal);
    // FIX #20: protect _stickyNode against concurrent access from heartbeat + task loops
    private readonly SemaphoreSlim _lock = new(1, 1);

    public NodeDiscoveryService(
        IHttpClientFactory httpClientFactory,
        IOptions<ClientOptions> options,
        SigningVerificationService signing,
        ILogger<NodeDiscoveryService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _signing = signing;
        _logger = logger;
    }

    public async Task<BackendNode?> GetBestNodeAsync(CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            if (_stickyNode is not null && await IsReachableAsync(_stickyNode, cancellationToken))
            {
                _logger.LogDebug("Using cached node {NodeId} ({Url})", _stickyNode.Id, _stickyNode.PublicUrl);
                return _stickyNode;
            }

            _logger.LogInformation("Fetching bootstrap manifest from {Url}", _options.ManagementUrl);

            SignedEnvelope<BootstrapManifest>? manifest;
            string raw;
            try
            {
                var client = _httpClientFactory.CreateClient();
                raw = await client.GetStringAsync(
                    $"{_options.ManagementUrl.TrimEnd('/')}/agent/bootstrap/{_options.TenantId}",
                    cancellationToken);
                manifest = JsonSerializer.Deserialize<SignedEnvelope<BootstrapManifest>>(raw, JsonOptions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to fetch bootstrap manifest from management server");
                return null;
            }

            if (manifest is null)
            {
                _logger.LogError("Bootstrap manifest was null or could not be parsed");
                return null;
            }

            BootstrapManifest payload;
            try
            {
                payload = _signing.VerifyJson<BootstrapManifest>(raw, "bootstrap_manifest");
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Bootstrap manifest signature verification FAILED — rejecting manifest");
                return null;
            }

            _logger.LogInformation("Manifest signature OK — probing {Count} candidate node(s)", payload.Nodes.Length);

            var candidates = payload.Nodes
                .Where(n => RequiredCapabilitiesSatisfied(n, payload.RequiredCapabilities))
                .OrderByDescending(n => n.Priority)
                .ThenByDescending(n => n.TrustScore)
                .ToArray();
            var probes = await Task.WhenAll(candidates.Select(n => ProbeAsync(n, cancellationToken)));
            _stickyNode = probes
                .Where(p => p.Reachable)
                .OrderByDescending(p => p.Node.Priority)
                .ThenByDescending(p => p.Node.TrustScore)
                .ThenBy(p => ScoreLatency(p.Node.Id, p.ElapsedMs))
                .Select(p => p.Node)
                .FirstOrDefault();

            if (_stickyNode is null)
                _logger.LogWarning("No reachable backend nodes found from {Count} candidate(s)", payload.Nodes.Length);
            else
                _logger.LogInformation("Selected node {NodeId} ({Url}) — latency {Ms}ms",
                    _stickyNode.Id, _stickyNode.PublicUrl,
                    probes.First(p => p.Node.Id == _stickyNode.Id).ElapsedMs);

            return _stickyNode;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<bool> IsReachableAsync(BackendNode node, CancellationToken ct)
        => (await ProbeAsync(node, ct)).Reachable;

    public void InvalidateStickyNode(string? nodeId = null)
    {
        if (_stickyNode is null) return;
        if (nodeId is null || string.Equals(_stickyNode.Id, nodeId, StringComparison.Ordinal))
        {
            _logger.LogWarning("Invalidating sticky backend node {NodeId}; next request will re-discover", _stickyNode.Id);
            _stickyNode = null;
        }
    }

    private async Task<NodeProbe> ProbeAsync(BackendNode node, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_options.NodeProbeTimeoutMilliseconds);
        var sw = Stopwatch.StartNew();
        try
        {
            var res = await _httpClientFactory.CreateClient()
                .GetAsync($"{node.PublicUrl.TrimEnd('/')}/live", cts.Token);
            _logger.LogDebug("Node probe {NodeId}: HTTP {Status} in {Ms}ms", node.Id, (int)res.StatusCode, sw.ElapsedMilliseconds);
            if (res.IsSuccessStatusCode) RecordLatency(node.Id, sw.ElapsedMilliseconds);
            return new NodeProbe(node, res.IsSuccessStatusCode, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Node probe {NodeId} unreachable: {Error}", node.Id, ex.Message);
            return new NodeProbe(node, false, long.MaxValue);
        }
    }

    private sealed record NodeProbe(BackendNode Node, bool Reachable, long ElapsedMs);

    private static bool RequiredCapabilitiesSatisfied(BackendNode node, string[]? required)
    {
        if (required is null || required.Length == 0) return true;
        var nodeCaps = node.Capabilities ?? [];
        return required.All(cap => nodeCaps.Contains(cap, StringComparer.OrdinalIgnoreCase));
    }

    private void RecordLatency(string nodeId, long elapsedMs)
    {
        _latencyEwma[nodeId] = _latencyEwma.TryGetValue(nodeId, out var previous)
            ? (previous * 0.7) + (elapsedMs * 0.3)
            : elapsedMs;
    }

    private double ScoreLatency(string nodeId, long measured)
        => _latencyEwma.TryGetValue(nodeId, out var ewma) ? ewma : measured;
}
