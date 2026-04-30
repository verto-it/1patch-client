using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32;
using OnePatch.Client.Models;

namespace OnePatch.Client.Providers;

public sealed class PlatformPackageProvider : IPackageProvider
{
    private readonly IHttpClientFactory _httpClientFactory;

    public PlatformPackageProvider(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public Task<IReadOnlyList<InstalledApp>> GetInstalledAppsAsync(CancellationToken cancellationToken)
    {
        if (IsWindows()) return Task.FromResult<IReadOnlyList<InstalledApp>>(GetWindowsApps());
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return GetLinuxAppsAsync(cancellationToken);
        return Task.FromResult<IReadOnlyList<InstalledApp>>([]);
    }

    public Task<string> UpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(task.SourceUrl))
        {
            return InstallDownloadedPackageAsync(task, cancellationToken);
        }

        var packageRef = task.PackageId ?? task.ProductCode;
        if (string.IsNullOrWhiteSpace(packageRef)) return Task.FromResult("Task rejected: missing package id or product code");
        if (IsWindows())
        {
            return RunAsync("winget", $"upgrade --id \"{packageRef}\" --accept-package-agreements --accept-source-agreements", cancellationToken);
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return RunAsync("apt-get", $"install --only-upgrade -y \"{packageRef}\"", cancellationToken);
        }
        return Task.FromResult("Task rejected: unsupported OS");
    }

    private async Task<string> InstallDownloadedPackageAsync(AgentTask task, CancellationToken cancellationToken)
    {
        if (!IsWindows()) return "Task rejected: downloaded MSI packages are currently supported on Windows only";
        if (string.IsNullOrWhiteSpace(task.Sha256)) return "Task rejected: missing package hash";

        var path = await DownloadAndVerifyAsync(task, cancellationToken);
        var args = string.IsNullOrWhiteSpace(task.InstallArgs) ? "/qn /norestart" : task.InstallArgs;
        if (!IsSafeMsiArgumentString(args)) return "Task rejected: install arguments are not allowlisted";
        return await RunAsync("msiexec.exe", $"/i \"{path}\" {args}", cancellationToken);
    }

    private async Task<string> DownloadAndVerifyAsync(AgentTask task, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient();
        var data = await client.GetByteArrayAsync(task.SourceUrl!, cancellationToken);
        var actual = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        if (!actual.Equals(task.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Package hash mismatch. Expected {task.Sha256}, got {actual}");
        }
        var path = Path.Combine(Path.GetTempPath(), $"1patch-{task.PackageArtifactId ?? task.Id}.msi");
        await File.WriteAllBytesAsync(path, data, cancellationToken);
        return path;
    }

    private static bool IsSafeMsiArgumentString(string args)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "/qn",
            "/quiet",
            "/norestart",
            "ALLUSERS=1",
            "REBOOT=ReallySuppress"
        };
        return args.Split(' ', StringSplitOptions.RemoveEmptyEntries).All(allowed.Contains);
    }

    [SupportedOSPlatformGuard("windows")]
    private static bool IsWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Called only after Windows OS check.")]
    private static List<InstalledApp> GetWindowsApps()
    {
        var apps = new List<InstalledApp>();
        string[] roots =
        [
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ];
        foreach (var root in roots)
        {
            using var key = Registry.LocalMachine.OpenSubKey(root);
            if (key is null) continue;
            foreach (var subkeyName in key.GetSubKeyNames())
            {
                using var subkey = key.OpenSubKey(subkeyName);
                var name = subkey?.GetValue("DisplayName") as string;
                if (string.IsNullOrWhiteSpace(name)) continue;
                apps.Add(new InstalledApp(
                    name,
                    subkey?.GetValue("Publisher") as string ?? "",
                    subkey?.GetValue("DisplayVersion") as string ?? "0.0.0",
                    subkeyName,
                    null));
            }
        }
        return apps;
    }

    private static async Task<IReadOnlyList<InstalledApp>> GetLinuxAppsAsync(CancellationToken cancellationToken)
    {
        var output = await RunAsync("dpkg-query", "-W -f='${Package}|${Version}|${Maintainer}\\n'", cancellationToken);
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('|'))
            .Where(parts => parts.Length >= 2)
            .Select(parts => new InstalledApp(parts[0], parts.Length > 2 ? parts[2] : "", parts[1], null, parts[0]))
            .ToList();
    }

    private static async Task<string> RunAsync(string fileName, string arguments, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {fileName}");
        var stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = await process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return string.IsNullOrWhiteSpace(stderr) ? stdout : $"{stdout}\n{stderr}";
    }
}
