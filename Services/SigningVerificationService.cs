using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;

namespace OnePatch.Client.Services;

public sealed class SigningVerificationService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ClientOptions _options;
    private readonly ILogger<SigningVerificationService> _logger;

    public SigningVerificationService(IOptions<ClientOptions> options, ILogger<SigningVerificationService> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public T VerifyJson<T>(string rawEnvelope, string expectedPayloadType)
    {
        using var doc = JsonDocument.Parse(rawEnvelope);
        var root = doc.RootElement;
        var envelope = root.Deserialize<SignedEnvelope<T>>(JsonOptions)
            ?? throw new InvalidOperationException("Signed payload could not be parsed");
        VerifyEnvelopeMetadata(envelope, expectedPayloadType);

        var publicKeyPem = _options.TrustedSigningPublicKeys[envelope.KeyId];
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(publicKeyPem.Replace("\\n", "\n"));
        var signature = Base64UrlDecode(envelope.Signature);
        var verified = ecdsa.VerifyData(
            Encoding.UTF8.GetBytes(CanonicalEnvelopeWithoutSignature(root)),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (!verified)
            throw new InvalidOperationException("Invalid signed payload signature");
        return envelope.Payload;
    }

    public T Verify<T>(SignedEnvelope<T> envelope, string expectedPayloadType)
    {
        VerifyEnvelopeMetadata(envelope, expectedPayloadType);
        var publicKeyPem = _options.TrustedSigningPublicKeys[envelope.KeyId];

        var unsigned = new
        {
            algorithm = envelope.Algorithm,
            expiresAt = envelope.ExpiresAt,
            issuedAt = envelope.IssuedAt,
            keyId = envelope.KeyId,
            nonce = envelope.Nonce,
            payload = envelope.Payload,
            payloadType = envelope.PayloadType,
            tenantId = envelope.TenantId,
        };

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(publicKeyPem.Replace("\\n", "\n"));
        var signature = Base64UrlDecode(envelope.Signature);
        var verified = ecdsa.VerifyData(
            Encoding.UTF8.GetBytes(CanonicalJson(JsonSerializer.SerializeToElement(unsigned, JsonOptions))),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (!verified)
            throw new InvalidOperationException("Invalid signed payload signature");

        _logger.LogDebug("Verified signed payload type={PayloadType} keyId={KeyId}", envelope.PayloadType, envelope.KeyId);
        return envelope.Payload;
    }

    private void VerifyEnvelopeMetadata<T>(SignedEnvelope<T> envelope, string expectedPayloadType)
    {
        if (!string.Equals(envelope.Algorithm, "ES256", StringComparison.Ordinal))
            throw new InvalidOperationException($"Unsupported signature algorithm '{envelope.Algorithm}'");
        if (!string.Equals(envelope.PayloadType, expectedPayloadType, StringComparison.Ordinal))
            throw new InvalidOperationException($"Unexpected payload type '{envelope.PayloadType}'");
        if (!DateTimeOffset.TryParse(envelope.ExpiresAt, out var expiresAt) ||
            !DateTimeOffset.TryParse(envelope.IssuedAt, out _))
            throw new InvalidOperationException("Invalid signed payload timestamps");
        if (expiresAt <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("Signed payload has expired");
        if (!_options.TrustedSigningPublicKeys.TryGetValue(envelope.KeyId, out var publicKeyPem) ||
            string.IsNullOrWhiteSpace(publicKeyPem))
            throw new InvalidOperationException($"Unknown signing key '{envelope.KeyId}'");
    }

    public static string CanonicalJson(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", value.EnumerateObject()
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .Select(p => $"{JsonSerializer.Serialize(p.Name)}:{CanonicalJson(p.Value)}")) + "}",
        JsonValueKind.Array => "[" + string.Join(",", value.EnumerateArray().Select(CanonicalJson)) + "]",
        _ => value.GetRawText(),
    };

    private static string CanonicalEnvelopeWithoutSignature(JsonElement envelope)
        => "{" + string.Join(",", envelope.EnumerateObject()
            .Where(p => !string.Equals(p.Name, "signature", StringComparison.Ordinal))
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .Select(p => $"{JsonSerializer.Serialize(p.Name)}:{CanonicalJson(p.Value)}")) + "}";

    private static byte[] Base64UrlDecode(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - base64.Length % 4) % 4), '=');
        return Convert.FromBase64String(base64);
    }
}
