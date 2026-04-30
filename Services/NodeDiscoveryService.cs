using System.Diagnostics;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;

namespace OnePatch.Client.Services;

public sealed class NodeDiscoveryService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ClientOptions _options;
    private BackendNode? _stickyNode;

    public NodeDiscoveryService(IHttpClientFactory httpClientFactory, IOptions<ClientOptions> options)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
    }

    public async Task<BackendNode?> GetBestNodeAsync(CancellationToken cancellationToken)
    {
        if (_stickyNode is not null && await IsReachableAsync(_stickyNode, cancellationToken)) return _stickyNode;

        var client = _httpClientFactory.CreateClient();
        var manifest = await client.GetFromJsonAsync<SignedManifest>(
            $"{_options.ManagementUrl.TrimEnd('/')}/agent/bootstrap/{_options.TenantId}",
            cancellationToken);

        var candidates = manifest?.Payload.Nodes ?? [];
        var probes = await Task.WhenAll(candidates.Select(node => ProbeAsync(node, cancellationToken)));
        _stickyNode = probes.Where(p => p.Reachable).OrderBy(p => p.ElapsedMs).Select(p => p.Node).FirstOrDefault();
        return _stickyNode;
    }

    private async Task<bool> IsReachableAsync(BackendNode node, CancellationToken cancellationToken)
    {
        return (await ProbeAsync(node, cancellationToken)).Reachable;
    }

    private async Task<NodeProbe> ProbeAsync(BackendNode node, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.NodeProbeTimeoutMilliseconds);
        var sw = Stopwatch.StartNew();
        try
        {
            var client = _httpClientFactory.CreateClient();
            var res = await client.GetAsync($"{node.PublicUrl.TrimEnd('/')}/health", timeout.Token);
            return new NodeProbe(node, res.IsSuccessStatusCode, sw.ElapsedMilliseconds);
        }
        catch
        {
            return new NodeProbe(node, false, long.MaxValue);
        }
    }

    private sealed record NodeProbe(BackendNode Node, bool Reachable, long ElapsedMs);
    private sealed record SignedManifest(ManifestPayload Payload, string Signature, string Algorithm);
    private sealed record ManifestPayload(string TenantId, DateTime IssuedAt, BackendNode[] Nodes);
}
