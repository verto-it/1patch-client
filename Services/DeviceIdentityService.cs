using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeviceId;
using Microsoft.Extensions.Logging;

namespace OnePatch.Client.Services;

public sealed class DeviceIdentityService
{
    private static readonly string StorePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "1Patch", "device.identity.json");

    public string DeviceId { get; }
    public string PublicKey { get; }

    // Private key bytes held in memory only — never exposed as a public property
    private readonly byte[] _privateKeyPkcs8;
    private readonly ILogger<DeviceIdentityService> _logger;

    public DeviceIdentityService(ILogger<DeviceIdentityService> logger)
    {
        _logger = logger;
        Directory.CreateDirectory(Path.GetDirectoryName(StorePath)!);

        if (File.Exists(StorePath))
        {
            _logger.LogInformation("Loading device identity from {Path}", StorePath);
            var stored = JsonSerializer.Deserialize<StoredIdentity>(File.ReadAllText(StorePath))!;
            DeviceId = stored.DeviceId;
            PublicKey = stored.PublicKey;
            _privateKeyPkcs8 = UnprotectKey(stored.ProtectedPrivateKey);
            _logger.LogInformation("Device identity loaded. DeviceId={DeviceId}", DeviceId);
            return;
        }

        _logger.LogInformation("No existing device identity — generating new identity");
        DeviceId = GenerateHardwareId();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        _privateKeyPkcs8 = key.ExportPkcs8PrivateKey();

        File.WriteAllText(StorePath, JsonSerializer.Serialize(
            new StoredIdentity(DeviceId, PublicKey, ProtectKey(_privateKeyPkcs8))));

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            File.SetUnixFileMode(StorePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        _logger.LogInformation("New device identity generated and stored. DeviceId={DeviceId}", DeviceId);
    }

    /// <summary>Signs data with the device private key (SHA256withECDSA, DER format).</summary>
    public byte[] SignData(byte[] data)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        key.ImportPkcs8PrivateKey(_privateKeyPkcs8, out _);
        return key.SignData(data, HashAlgorithmName.SHA256);
    }


    /// <summary>
    /// Signs bytes with the device ES256 private key using IeeeP1363 fixed-field
    /// concatenation (r||s, 64 bytes). Used by BackendNodeClient for per-request
    /// device authentication headers (x-device-sig).
    /// </summary>
    public byte[] SignBytes(byte[] data)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        key.ImportPkcs8PrivateKey(_privateKeyPkcs8, out _);
        return key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
    private static string GenerateHardwareId()
    {
        var raw = new DeviceIdBuilder()
            .AddMachineName()
            .AddOsVersion()
            .OnWindows(w => w.AddMachineGuid().AddProcessorId().AddMotherboardSerialNumber())
            .OnLinux(l => l.AddMachineId().AddProductUuid())
            .ToString();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }

    private static string ProtectKey(byte[] keyBytes)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return Convert.ToBase64String(ProtectedData.Protect(keyBytes, null, DataProtectionScope.LocalMachine));
        // Linux: file is chmod 600 — no additional wrapping needed
        return Convert.ToBase64String(keyBytes);
    }

    private static byte[] UnprotectKey(string base64)
    {
        var data = Convert.FromBase64String(base64);
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return ProtectedData.Unprotect(data, null, DataProtectionScope.LocalMachine);
        return data;
    }

    private sealed record StoredIdentity(string DeviceId, string PublicKey, string ProtectedPrivateKey);
}
