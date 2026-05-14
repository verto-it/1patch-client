using System.Security.Cryptography;
using System.ComponentModel;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnePatch.Client.Models;
using OnePatch.Client.Providers;
using OnePatch.Client.Services;

var (privateKey, publicKey) = CreateKeys();
var verifier = new SigningVerificationService(
    Options.Create(new ClientOptions
    {
        TenantId = "default",
        TrustedSigningKeys = new Dictionary<string, SigningKeyMetadata>
        {
            ["main"] = KeyMeta("main", "bootstrap_manifest", publicKey),
            ["task"] = KeyMeta("task", "task_bundle", publicKey)
        }
    }),
    new TestLogger<SigningVerificationService>());

var valid = Sign(privateKey, "main", DateTimeOffset.UtcNow.AddMinutes(10), new BootstrapManifest([]));
verifier.VerifyJson<BootstrapManifest>(valid, "bootstrap_manifest");

var serverStyleJson = new JsonSerializerOptions(JsonSerializerDefaults.Web)
{
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
};
var serverStyleManifest = new BootstrapManifest(
    [new BackendNode("node-1", "http://localhost:4200", Region: "local", Site: null, Capabilities: ["agent"], HealthState: "healthy", TrustScore: 100, LatencyMs: null, Priority: 10, Weight: 100)],
    TenantId: "default",
    IssuedAt: DateTimeOffset.UtcNow.ToString("O"),
    PolicyId: null,
    RequiredCapabilities: ["agent"],
    Failover: ["node-1"]);
verifier.VerifyJson<BootstrapManifest>(
    Sign(privateKey, "main", DateTimeOffset.UtcNow.AddMinutes(10), serverStyleManifest, serializerOptions: serverStyleJson),
    "bootstrap_manifest");

ExpectReject("modified manifest", () =>
    verifier.VerifyJson<BootstrapManifest>(valid.Replace("\"nodes\":[]", "\"nodes\":[{\"id\":\"evil\",\"publicUrl\":\"https://evil\"}]"), "bootstrap_manifest"));

ExpectReject("unknown key", () =>
    verifier.VerifyJson<BootstrapManifest>(Sign(privateKey, "unknown", DateTimeOffset.UtcNow.AddMinutes(10), new BootstrapManifest([])), "bootstrap_manifest"));

ExpectReject("wrong key scope", () =>
    verifier.VerifyJson<BootstrapManifest>(Sign(privateKey, "task", DateTimeOffset.UtcNow.AddMinutes(10), new BootstrapManifest([])), "bootstrap_manifest"));

ExpectReject("wildcard key", () =>
{
    var wildcardVerifier = new SigningVerificationService(
        Options.Create(new ClientOptions
        {
            TenantId = "default",
            TrustedSigningKeys = new Dictionary<string, SigningKeyMetadata> { ["main"] = KeyMeta("main", "*", publicKey) }
        }),
        new TestLogger<SigningVerificationService>());
    wildcardVerifier.VerifyJson<BootstrapManifest>(valid, "bootstrap_manifest");
});

ExpectReject("dev key", () =>
{
    var devVerifier = new SigningVerificationService(
        Options.Create(new ClientOptions
        {
            TenantId = "default",
            TrustedSigningKeys = new Dictionary<string, SigningKeyMetadata> { ["main"] = KeyMeta("main", "bootstrap_manifest", publicKey, true) }
        }),
        new TestLogger<SigningVerificationService>());
    devVerifier.VerifyJson<BootstrapManifest>(valid, "bootstrap_manifest");
});

ExpectReject("expired payload", () =>
    verifier.VerifyJson<BootstrapManifest>(Sign(privateKey, "main", DateTimeOffset.UtcNow.AddMinutes(-1), new BootstrapManifest([])), "bootstrap_manifest"));

ExpectReject("tenant mismatch", () =>
    verifier.VerifyJson<BootstrapManifest>(Sign(privateKey, "main", DateTimeOffset.UtcNow.AddMinutes(10), new BootstrapManifest([]), "bootstrap_manifest", "other"), "bootstrap_manifest"));

var taskBundle = new TaskBundle([new AgentTask("task-1", "device-1", null, "refresh_inventory", null, null, null, null, null, null, null, null, null, "latest", null, null, null)], null);
var signedTask = Sign(privateKey, "task", DateTimeOffset.UtcNow.AddMinutes(10), taskBundle, "task_bundle");
verifier.VerifyJson<TaskBundle>(signedTask, "task_bundle");
ExpectReject("tampered task", () =>
    verifier.VerifyJson<TaskBundle>(signedTask.Replace("\"refresh_inventory\"", "\"update_package\""), "task_bundle"));

var dpkgApps = PlatformPackageProvider.ParseDpkgQueryOutput("""
apt|2.7.14build2|Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
openssl|3.0.13-0ubuntu3.1|Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
""");
Expect(dpkgApps.Count == 2, "dpkg parser should return two packages");
Expect(dpkgApps[0].Name == "apt" && dpkgApps[0].PackageId == "apt", "dpkg parser should use package name as packageId");

var wingetMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
PlatformPackageProvider.ParseWingetListInto("""
Name           Id             Version
--------------------------------------
Google Chrome  Google.Chrome  124.0.0
""", wingetMap);
Expect(wingetMap["Google Chrome"] == "Google.Chrome", "winget parser should map display name to package id");

var chocoApps = PlatformPackageProvider.ParseChocolateyList("""
git|2.45.1
malformed row
nodejs-lts|20.11.1
""");
Expect(chocoApps.Count == 2, "Chocolatey parser should return limit-output package rows");
Expect(chocoApps[0].PackageManager == "chocolatey" && chocoApps[0].PackageScope == "system", "Chocolatey parser should stamp manager metadata");

var scoopRoot = Path.Combine(Path.GetTempPath(), $"1patch-scoop-test-{Guid.NewGuid():N}");
Directory.CreateDirectory(Path.Combine(scoopRoot, "apps", "git", "2.45.1"));
Directory.CreateDirectory(Path.Combine(scoopRoot, "apps", "git", "current"));
try
{
    var scoopApps = PlatformPackageProvider.ScanScoopAppsFromRoots([(Path.Combine(scoopRoot, "apps"), "global")]);
    Expect(scoopApps.Count == 1, "Scoop scanner should discover app directories");
    Expect(scoopApps[0].PackageManager == "scoop" && scoopApps[0].PackageScope == "global", "Scoop scanner should stamp manager metadata");
    Expect(scoopApps[0].Version == "2.45.1", "Scoop scanner should ignore current and use installed version directories");
}
finally
{
    Directory.Delete(scoopRoot, recursive: true);
}

var linuxRunner = new RecordingRunner(new ProcessResult(0, "apt upgraded"));
var linuxProvider = LinuxProvider(linuxRunner, isRoot: true);
var linuxOutput = await linuxProvider.UpdateAsync(UpdateTask(packageId: "openssl"), CancellationToken.None);
Expect(linuxOutput == "apt upgraded", "linux apt update should return command output on success");
Expect(linuxRunner.Calls.Count == 1, "linux apt update should invoke one command");
Expect(linuxRunner.Calls[0].FileName == "apt-get", "linux apt update should invoke apt-get");
Expect(linuxRunner.Calls[0].Arguments.SequenceEqual(["install", "--only-upgrade", "-y", "openssl"]), "linux apt update should pass exact apt-get arguments");
Expect(linuxRunner.Calls[0].Environment?["DEBIAN_FRONTEND"] == "noninteractive", "linux apt update should set DEBIAN_FRONTEND");

var missingPackageRunner = new RecordingRunner(new ProcessResult(0, "unused"));
var missingPackageResult = await LinuxProvider(missingPackageRunner, isRoot: true).UpdateAsync(UpdateTask(packageId: null), CancellationToken.None);
Expect(missingPackageResult.StartsWith("Task rejected: missing or unsafe apt package name", StringComparison.Ordinal), "linux update should reject missing packageId");
Expect(missingPackageRunner.Calls.Count == 0, "linux update should not call apt-get without packageId");

var unsafePackageResult = await LinuxProvider(new RecordingRunner(new ProcessResult(0, "unused")), isRoot: true)
    .UpdateAsync(UpdateTask(packageId: "Bad Package;rm"), CancellationToken.None);
Expect(unsafePackageResult.StartsWith("Task rejected: missing or unsafe apt package name", StringComparison.Ordinal), "linux update should reject unsafe packageId");

var nonRootResult = await LinuxProvider(new RecordingRunner(new ProcessResult(0, "unused")), isRoot: false)
    .UpdateAsync(UpdateTask(packageId: "openssl"), CancellationToken.None);
Expect(nonRootResult.Contains("run as root", StringComparison.OrdinalIgnoreCase), "linux update should reject non-root apt execution");

var missingAptResult = await LinuxProvider(new RecordingRunner(new Win32Exception("not found")), isRoot: true)
    .UpdateAsync(UpdateTask(packageId: "openssl"), CancellationToken.None);
Expect(missingAptResult.Contains("apt-get was not found", StringComparison.OrdinalIgnoreCase), "linux update should report missing apt-get");

var chocoRunner = new RecordingRunner(new ProcessResult(0, "upgraded"));
var chocoResult = await WindowsProvider(chocoRunner).UpdateAsync(UpdateTask("git", packageManager: "chocolatey"), CancellationToken.None);
Expect(chocoResult == "upgraded", "Chocolatey update should return command output on success");
Expect(chocoRunner.Calls[0].FileName == "choco", "Chocolatey update should call choco");
Expect(chocoRunner.Calls[0].Arguments.SequenceEqual(["upgrade", "git", "-y", "--limit-output"]), "Chocolatey update should pass exact upgrade arguments");

var chocoMissing = await WindowsProvider(new RecordingRunner(new Win32Exception("not found")))
    .UpdateAsync(UpdateTask("git", packageManager: "chocolatey"), CancellationToken.None);
Expect(chocoMissing.Contains("Chocolatey executable was not found", StringComparison.OrdinalIgnoreCase), "Chocolatey update should report missing choco.exe");

var chocoNoMatch = await WindowsProvider(new RecordingRunner(new ProcessResult(1, "not installed")))
    .UpdateAsync(UpdateTask("git", packageManager: "chocolatey"), CancellationToken.None);
Expect(chocoNoMatch.Contains("no Chocolatey match", StringComparison.OrdinalIgnoreCase), "Chocolatey update should report missing package match");

var scoopRunner = new RecordingRunner(new ProcessResult(0, "updated"));
var scoopResult = await WindowsProvider(scoopRunner).UpdateAsync(UpdateTask("git", packageManager: "scoop", packageScope: "global"), CancellationToken.None);
Expect(scoopResult == "updated", "Scoop global update should return command output on success");
Expect(scoopRunner.Calls[0].FileName == "scoop", "Scoop update should call scoop");
Expect(scoopRunner.Calls[0].Arguments.SequenceEqual(["update", "git", "--global"]), "Scoop global update should pass --global");

var userScoopRunner = new RecordingRunner(new ProcessResult(0, "unused"));
var userScoopResult = await WindowsProvider(userScoopRunner).UpdateAsync(UpdateTask("git", packageManager: "scoop", packageScope: "user"), CancellationToken.None);
Expect(userScoopResult.Contains("inventory-only", StringComparison.OrdinalIgnoreCase), "Scoop user-scope update should be rejected");
Expect(userScoopRunner.Calls.Count == 0, "Scoop user-scope update should not execute scoop");

var wingetRunner = new RecordingRunner(new ProcessResult(0, "winget upgraded"));
var legacyWingetResult = await WindowsProvider(wingetRunner).UpdateAsync(UpdateTask("Git.Git"), CancellationToken.None);
Expect(legacyWingetResult == "winget upgraded", "Legacy Windows task without packageManager should route to winget");
Expect(wingetRunner.Calls[0].FileName == "winget", "Legacy Windows task should call winget");

Console.WriteLine("Client signing verification tests passed.");

static (ECDsa privateKey, string publicKey) CreateKeys()
{
    var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    return (key, key.ExportSubjectPublicKeyInfoPem());
}

static string Sign<T>(
    ECDsa key,
    string keyId,
    DateTimeOffset expiresAt,
    T payload,
    string payloadType = "bootstrap_manifest",
    string tenantId = "default",
    JsonSerializerOptions? serializerOptions = null)
{
    var jsonOptions = serializerOptions ?? new JsonSerializerOptions(JsonSerializerDefaults.Web);
    var payloadHash = ComputePayloadHash(payload, jsonOptions);
    var unsigned = new
    {
        algorithm = "ES256",
        expiresAt = expiresAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
        issuedAt = DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
        keyId,
        nonce = Guid.NewGuid().ToString(),
        payload,
        payloadHash,
        scope = payloadType,
        payloadType,
        tenantId,
    };
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
        unsigned.payloadHash,
        unsigned.scope,
        unsigned.payload,
        signature,
    }, jsonOptions);
}

static SigningKeyMetadata KeyMeta(string keyId, string scope, string publicKey, bool isDev = false) =>
    new()
    {
        KeyId = keyId,
        Scope = scope,
        Status = "active",
        PublicKeyPem = publicKey,
        IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
        IsDev = isDev,
        Algorithm = "ES256",
    };

static string ComputePayloadHash<T>(T payload, JsonSerializerOptions options)
{
    var canonical = SigningVerificationService.CanonicalJson(JsonSerializer.SerializeToElement(payload, options));
    return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
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

static void Expect(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static AgentTask UpdateTask(string? packageId, string? packageManager = null, string? packageScope = null) =>
    new("task-apt", "device-1", "default", "update_package", "OpenSSL", null, packageId, packageManager, packageScope, null, null, null, null, "latest", null, null, null);

static PlatformPackageProvider LinuxProvider(RecordingRunner runner, bool isRoot) =>
    new(null!, Options.Create(new ClientOptions()), null!, new FakePlatform(isRoot, isWindows: false), runner, new TestLogger<PlatformPackageProvider>());

static PlatformPackageProvider WindowsProvider(RecordingRunner runner) =>
    new(null!, Options.Create(new ClientOptions()), null!, new FakePlatform(isRoot: false, isWindows: true), runner, new TestLogger<PlatformPackageProvider>());

sealed class FakePlatform(bool isRoot, bool isWindows) : IPlatformInfo
{
    public bool IsWindows => isWindows;
    public bool IsLinux => !isWindows;
    public bool IsLinuxRoot => IsLinux && isRoot;
    public string CommonApplicationDataPath => isWindows ? Path.GetTempPath() : "/var/lib";
}

sealed class RecordingRunner : IProcessRunner
{
    private readonly ProcessResult? _result;
    private readonly Exception? _exception;
    public List<CommandCall> Calls { get; } = [];

    public RecordingRunner(ProcessResult result)
    {
        _result = result;
    }

    public RecordingRunner(Exception exception)
    {
        _exception = exception;
    }

    public Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? environment,
        CancellationToken cancellationToken)
    {
        Calls.Add(new CommandCall(fileName, arguments.ToArray(), environment is null ? null : new Dictionary<string, string>(environment)));
        if (_exception is not null) throw _exception;
        return Task.FromResult(_result!);
    }
}

sealed record CommandCall(string FileName, string[] Arguments, IReadOnlyDictionary<string, string>? Environment);

sealed class TestLogger<T> : ILogger<T>
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => false;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
}
