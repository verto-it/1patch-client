using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;
using OnePatch.Client.Services;

var (privateKey, publicKey) = CreateKeys();
var verifier = new SigningVerificationService(
    Options.Create(new ClientOptions
    {
        TrustedSigningPublicKeys = new Dictionary<string, string> { ["main"] = publicKey }
    }),
    new TestLogger<SigningVerificationService>());

var valid = Sign(privateKey, "main", DateTimeOffset.UtcNow.AddMinutes(10), new BootstrapManifest([]));
verifier.VerifyJson<BootstrapManifest>(valid, "bootstrap_manifest");

ExpectReject("modified manifest", () =>
    verifier.VerifyJson<BootstrapManifest>(valid.Replace("\"nodes\":[]", "\"nodes\":[{\"id\":\"evil\",\"publicUrl\":\"https://evil\"}]"), "bootstrap_manifest"));

ExpectReject("unknown key", () =>
    verifier.VerifyJson<BootstrapManifest>(Sign(privateKey, "unknown", DateTimeOffset.UtcNow.AddMinutes(10), new BootstrapManifest([])), "bootstrap_manifest"));

ExpectReject("expired payload", () =>
    verifier.VerifyJson<BootstrapManifest>(Sign(privateKey, "main", DateTimeOffset.UtcNow.AddMinutes(-1), new BootstrapManifest([])), "bootstrap_manifest"));

var taskBundle = new TaskBundle([new AgentTask("task-1", "device-1", "refresh_inventory", null, null, null, null, null, null, null, "latest")]);
var signedTask = Sign(privateKey, "main", DateTimeOffset.UtcNow.AddMinutes(10), taskBundle, "task_bundle");
verifier.VerifyJson<TaskBundle>(signedTask, "task_bundle");
ExpectReject("tampered task", () =>
    verifier.VerifyJson<TaskBundle>(signedTask.Replace("\"refresh_inventory\"", "\"update_package\""), "task_bundle"));

Console.WriteLine("Client signing verification tests passed.");

static (ECDsa privateKey, string publicKey) CreateKeys()
{
    var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    return (key, key.ExportSubjectPublicKeyInfoPem());
}

static string Sign<T>(ECDsa key, string keyId, DateTimeOffset expiresAt, T payload, string payloadType = "bootstrap_manifest")
{
    var unsigned = new
    {
        algorithm = "ES256",
        expiresAt = expiresAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
        issuedAt = DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
        keyId,
        nonce = Guid.NewGuid().ToString(),
        payload,
        payloadType,
        tenantId = "default",
    };
    var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
    var canonical = SigningVerificationService.CanonicalJson(JsonSerializer.SerializeToElement(unsigned, jsonOptions));
    var signature = Base64UrlEncode(key.SignData(
        Encoding.UTF8.GetBytes(canonical),
        HashAlgorithmName.SHA256,
        DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    return JsonSerializer.Serialize(new
    {
        unsigned.algorithm,
        unsigned.keyId,
        unsigned.payloadType,
        unsigned.tenantId,
        unsigned.issuedAt,
        unsigned.expiresAt,
        unsigned.nonce,
        unsigned.payload,
        signature,
    }, jsonOptions);
}

static string Base64UrlEncode(byte[] value) =>
    Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

static void ExpectReject(string name, Action action)
{
    try
    {
        action();
        throw new Exception($"Expected rejection for {name}");
    }
    catch (InvalidOperationException)
    {
    }
}

sealed class TestLogger<T> : ILogger<T>
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => false;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
}
