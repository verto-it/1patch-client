using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;

namespace OnePatch.Client.Services;

public sealed class SigningVerificationService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    // TypeScript's canonicalJson() skips properties whose value is undefined.
    // Those properties are absent on the wire, but after deserialising into C#
    // records the same optional fields become null. Keep nulls out of canonical
    // hashes/signatures so verification matches the bytes signed by the server.
    private static readonly JsonSerializerOptions CanonicalOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
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
        var rawPayload = root.GetProperty("payload");
        VerifyEnvelopeMetadata(envelope, expectedPayloadType, rawPayload);

        var keyMeta = ResolveTrustedKey(envelope.KeyId, expectedPayloadType, envelope.TenantId);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(keyMeta.PublicKeyPem.Replace("\\n", "\n"));
        var signature = Base64UrlDecode(envelope.Signature);
        var verified = ecdsa.VerifyData(
            Encoding.UTF8.GetBytes(CanonicalEnvelopeWithoutSignature(root)),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (!verified)
            throw new InvalidOperationException("Invalid signed payload signature");
        if (envelope.PayloadHash is not null && !string.Equals(envelope.PayloadHash, ComputePayloadHash(rawPayload), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Signed payload hash mismatch");
        return envelope.Payload;
    }

    public T Verify<T>(SignedEnvelope<T> envelope, string expectedPayloadType)
    {
        VerifyEnvelopeMetadata(envelope, expectedPayloadType);
        var keyMeta = ResolveTrustedKey(envelope.KeyId, expectedPayloadType, envelope.TenantId);

        var unsigned = new
        {
            algorithm = envelope.Algorithm,
            expiresAt = envelope.ExpiresAt,
            issuedAt = envelope.IssuedAt,
            keyId = envelope.KeyId,
            nonce = envelope.Nonce,
            payload = envelope.Payload,
            payloadHash = envelope.PayloadHash,
            scope = envelope.Scope,
            payloadType = envelope.PayloadType,
            tenantId = envelope.TenantId,
        };

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(keyMeta.PublicKeyPem.Replace("\\n", "\n"));
        var signature = Base64UrlDecode(envelope.Signature);
        var verified = ecdsa.VerifyData(
            Encoding.UTF8.GetBytes(CanonicalJson(JsonSerializer.SerializeToElement(unsigned, CanonicalOptions))),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (!verified)
            throw new InvalidOperationException("Invalid signed payload signature");
        if (envelope.PayloadHash is not null && !string.Equals(envelope.PayloadHash, ComputePayloadHash(envelope.Payload), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Signed payload hash mismatch");

        _logger.LogDebug("Verified signed payload type={PayloadType} keyId={KeyId}", envelope.PayloadType, envelope.KeyId);
        return envelope.Payload;
    }

    private void VerifyEnvelopeMetadata<T>(SignedEnvelope<T> envelope, string expectedPayloadType, JsonElement? rawPayload = null)
    {
        if (!string.Equals(envelope.Algorithm, "ES256", StringComparison.Ordinal))
            throw new InvalidOperationException($"Unsupported signature algorithm '{envelope.Algorithm}'");
        if (string.IsNullOrWhiteSpace(envelope.Scope))
            throw new InvalidOperationException("Signed payload is missing scope");
        if (!string.Equals(envelope.Scope, envelope.PayloadType, StringComparison.Ordinal))
            throw new InvalidOperationException($"Signed payload scope '{envelope.Scope}' does not match payloadType '{envelope.PayloadType}'");
        if (!string.Equals(envelope.PayloadType, expectedPayloadType, StringComparison.Ordinal))
            throw new InvalidOperationException($"Unexpected payload type '{envelope.PayloadType}'");
        if (!string.Equals(envelope.TenantId, _options.TenantId, StringComparison.Ordinal))
            throw new InvalidOperationException($"TenantId mismatch: envelope={envelope.TenantId} client={_options.TenantId}");
        if (!DateTimeOffset.TryParse(envelope.ExpiresAt, out var expiresAt) ||
            !DateTimeOffset.TryParse(envelope.IssuedAt, out _))
            throw new InvalidOperationException("Invalid signed payload timestamps");
        if (expiresAt <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("Signed payload has expired");
        if (string.IsNullOrWhiteSpace(envelope.PayloadHash))
            throw new InvalidOperationException("Signed payload is missing payloadHash");
        var computedPayloadHash = rawPayload is { } payloadElement
            ? ComputePayloadHash(payloadElement)
            : ComputePayloadHash(envelope.Payload);
        if (!string.Equals(envelope.PayloadHash, computedPayloadHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Signed payload hash mismatch");
        _ = ResolveTrustedKey(envelope.KeyId, expectedPayloadType, envelope.TenantId);
    }

    private SigningKeyMetadata ResolveTrustedKey(string keyId, string expectedScope, string tenantId)
    {
        SigningKeyMetadata? meta = null;
        if (!_options.TrustedSigningKeys.TryGetValue(keyId, out meta))
        {
            if (IsDevelopment() &&
                _options.TrustedSigningKeys.Count == 0 &&
                _options.TrustedSigningPublicKeys.TryGetValue(keyId, out var legacyPem) &&
                !string.IsNullOrWhiteSpace(legacyPem))
            {
                meta = new SigningKeyMetadata { KeyId = keyId, Scope = expectedScope, Status = "active", PublicKeyPem = legacyPem, IssuedAt = DateTimeOffset.UtcNow.ToString("O"), IsDev = true, Algorithm = "ES256" };
            }
            else
            {
                throw new InvalidOperationException($"Unknown signing key '{keyId}'");
            }
        }

        if (string.Equals(meta.Scope, "*", StringComparison.Ordinal) && !IsDevelopment())
            throw new InvalidOperationException($"Wildcard signing key '{keyId}' is not trusted");
        if (!string.Equals(meta.Scope, "*", StringComparison.Ordinal) && !string.Equals(meta.Scope, expectedScope, StringComparison.Ordinal))
            throw new InvalidOperationException($"Signing key '{keyId}' is scoped to '{meta.Scope}', not '{expectedScope}'");
        if (!string.Equals(meta.Algorithm, "ES256", StringComparison.Ordinal))
            throw new InvalidOperationException($"Unsupported signing key algorithm '{meta.Algorithm}'");
        if (string.Equals(meta.Status, "revoked", StringComparison.Ordinal))
            throw new InvalidOperationException($"Signing key '{keyId}' has been revoked");
        if (string.Equals(meta.Status, "retired", StringComparison.Ordinal))
        {
            if (!DateTimeOffset.TryParse(meta.RetirementDeadline, out var deadline) || deadline <= DateTimeOffset.UtcNow)
                throw new InvalidOperationException($"Signing key '{keyId}' retirement deadline has passed");
        }
        if (meta.IsDev && !IsDevelopment())
            throw new InvalidOperationException($"Dev signing key '{keyId}' is not trusted");
        if (meta.AllowedTenants is { Length: > 0 } && !meta.AllowedTenants.Contains(tenantId, StringComparer.Ordinal))
            throw new InvalidOperationException($"Signing key '{keyId}' is not allowed for tenant '{tenantId}'");
        if (string.IsNullOrWhiteSpace(meta.PublicKeyPem))
            throw new InvalidOperationException($"Signing key '{keyId}' is missing public key material");
        return meta;
    }

    private static bool IsDevelopment()
        => string.Equals(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase);

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

    private static string ComputePayloadHash<T>(T payload)
    {
        var json = JsonSerializer.Serialize(payload, CanonicalOptions);
        var canonical = CanonicalJson(JsonDocument.Parse(json).RootElement);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static string ComputePayloadHash(JsonElement payload)
    {
        var canonical = CanonicalJson(payload);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }
}
