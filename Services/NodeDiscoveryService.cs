using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
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
    private readonly ILogger<NodeDiscoveryService> _logger;
    private BackendNode? _stickyNode;
    // FIX #20: protect _stickyNode against concurrent access from heartbeat + task loops
    private readonly SemaphoreSlim _lock = new(1, 1);

    public NodeDiscoveryService(
        IHttpClientFactory httpClientFactory,
        IOptions<ClientOptions> options,
        ILogger<NodeDiscoveryService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
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

            SignedManifest? manifest;
            try
            {
                var client = _httpClientFactory.CreateClient();
                var raw = await client.GetStringAsync(
                    $"{_options.ManagementUrl.TrimEnd('/')}/agent/bootstrap/{_options.TenantId}",
                    cancellationToken);
                manifest = ParseSignedManifest(raw);
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

            // FIX #2: verify HMAC signature before trusting any node URLs
            if (!VerifyManifestSignature(manifest))
            {
                _logger.LogCritical("Bootstrap manifest signature verification FAILED — rejecting manifest (possible MITM)");
                return null;
            }

            _logger.LogInformation("Manifest signature OK — probing {Count} candidate node(s)", manifest.Payload.Nodes.Length);

            var probes = await Task.WhenAll(manifest.Payload.Nodes.Select(n => ProbeAsync(n, cancellationToken)));
            _stickyNode = probes
                .Where(p => p.Reachable)
                .OrderBy(p => p.ElapsedMs)
                .Select(p => p.Node)
                .FirstOrDefault();

            if (_stickyNode is null)
                _logger.LogWarning("No reachable backend nodes found from {Count} candidate(s)", manifest.Payload.Nodes.Length);
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

    private static SignedManifest? ParseSignedManifest(string raw)
    {
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;

        if (!root.TryGetProperty("payload", out var payloadElement) ||
            !root.TryGetProperty("signature", out var signatureElement))
        {
            return null;
        }

        var payloadJson = payloadElement.GetRawText();
        var payload = payloadElement.Deserialize<ManifestPayload>(JsonOptions);
        var signature = signatureElement.GetString();
        var algorithm = root.TryGetProperty("algorithm", out var algorithmElement)
            ? algorithmElement.GetString() ?? "HMAC-SHA256"
            : "HMAC-SHA256";

        return payload is null || string.IsNullOrWhiteSpace(signature)
            ? null
            : new SignedManifest(payload, payloadJson, signature, algorithm);
    }

    // FIX #2: HMAC-SHA256 manifest verification
    private bool VerifyManifestSignature(SignedManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(_options.ManifestSigningSecret))
        {
            _logger.LogError("ManifestSigningSecret is not configured — cannot verify bootstrap manifest");
            return false;
        }
        var expected = Convert.ToHexString(
            HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(_options.ManifestSigningSecret),
                Encoding.UTF8.GetBytes(manifest.PayloadJson))).ToLowerInvariant();
        // Constant-time comparison prevents timing attacks
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(manifest.Signature.ToLowerInvariant()));
    }

    private async Task<bool> IsReachableAsync(BackendNode node, CancellationToken ct)
        => (await ProbeAsync(node, ct)).Reachable;

    private async Task<NodeProbe> ProbeAsync(BackendNode node, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_options.NodeProbeTimeoutMilliseconds);
        var sw = Stopwatch.StartNew();
        try
        {
            var res = await _httpClientFactory.CreateClient()
                .GetAsync($"{node.PublicUrl.TrimEnd('/')}/health", cts.Token);
            _logger.LogDebug("Node probe {NodeId}: HTTP {Status} in {Ms}ms", node.Id, (int)res.StatusCode, sw.ElapsedMilliseconds);
            return new NodeProbe(node, res.IsSuccessStatusCode, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Node probe {NodeId} unreachable: {Error}", node.Id, ex.Message);
            return new NodeProbe(node, false, long.MaxValue);
        }
    }

    private sealed record NodeProbe(BackendNode Node, bool Reachable, long ElapsedMs);
    private sealed record SignedManifest(ManifestPayload Payload, string PayloadJson, string Signature, string Algorithm);
    private sealed record ManifestPayload(string TenantId, DateTime IssuedAt, BackendNode[] Nodes);
}
