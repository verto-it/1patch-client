using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeviceId;

namespace OnePatch.Client.Services;

public sealed class DeviceIdentityService
{
    private const string StorePath = "device.identity.json";

    public string DeviceId { get; }
    public string PublicKey { get; }
    public string PrivateKey { get; }

    public DeviceIdentityService()
    {
        if (File.Exists(StorePath))
        {
            var stored = JsonSerializer.Deserialize<StoredIdentity>(File.ReadAllText(StorePath))!;
            DeviceId = stored.DeviceId;
            PublicKey = stored.PublicKey;
            PrivateKey = stored.PrivateKey;
            return;
        }

        DeviceId = GenerateHardwareId();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        PrivateKey = Convert.ToBase64String(key.ExportPkcs8PrivateKey());
        File.WriteAllText(StorePath, JsonSerializer.Serialize(new StoredIdentity(DeviceId, PublicKey, PrivateKey)));
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

    private sealed record StoredIdentity(string DeviceId, string PublicKey, string PrivateKey);
}
