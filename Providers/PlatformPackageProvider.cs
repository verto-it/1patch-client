using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using OnePatch.Client.Models;
using OnePatch.Client.Services;

namespace OnePatch.Client.Providers;

public sealed class PlatformPackageProvider : IPackageProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ClientOptions _options;
    private readonly ILogger<PlatformPackageProvider> _logger;
    private readonly NodeDiscoveryService _nodes;

    // Package names are passed as ProcessStartInfo.ArgumentList entries, never through a shell.
    private static readonly Regex SafePackageIdPattern = new(@"^[A-Za-z0-9._\-]+$", RegexOptions.Compiled);
    private static readonly Regex SafeAptPackagePattern = new(@"^[a-z0-9][a-z0-9+.\-]*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public PlatformPackageProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<ClientOptions> options,
        NodeDiscoveryService nodes,
        ILogger<PlatformPackageProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _nodes = nodes;
        _logger = logger;
    }

    public Task<IReadOnlyList<InstalledApp>> GetInstalledAppsAsync(CancellationToken cancellationToken)
    {
        if (IsWindows())
        {
            _logger.LogInformation("Enumerating installed Windows applications");
            return GetWindowsAppsAsync(cancellationToken);
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            _logger.LogInformation("Enumerating installed Linux (dpkg) applications");
            return GetLinuxAppsAsync(cancellationToken);
        }
        _logger.LogWarning("GetInstalledApps: unsupported OS — returning empty list");
        return Task.FromResult<IReadOnlyList<InstalledApp>>([]);
    }

    [SuppressMessage("Interoperability", "CA1416", Justification = "Called only after Windows OS check.")]
    private async Task<IReadOnlyList<InstalledApp>> GetWindowsAppsAsync(CancellationToken cancellationToken)
    {
        var apps = GetWindowsRegistryApps();
        var wingetIds = await TryBuildWingetIdMapAsync(cancellationToken);
        if (wingetIds.Count == 0) return apps;
        return apps
            .Select(a => wingetIds.TryGetValue(a.Name, out var id) ? a with { PackageId = id } : a)
            .ToList();
    }

    private async Task<Dictionary<string, string>> TryBuildWingetIdMapAsync(CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var output = await RunAsync("winget",
                ["list", "--source", "winget", "--disable-interactivity", "--accept-source-agreements"],
                cancellationToken);
            ParseWingetListInto(output, map);
            _logger.LogInformation("winget list resolved {Count} package IDs", map.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "winget list failed — packageId will be absent from Windows inventory");
        }
        return map;
    }

    private static void ParseWingetListInto(string output, Dictionary<string, string> map)
    {
        var lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);

        // Find the header line — it contains both "Name" and "Id" as column headers
        int headerIdx = -1;
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains("Name", StringComparison.OrdinalIgnoreCase) &&
                Regex.IsMatch(lines[i], @"\bId\b"))
            {
                headerIdx = i;
                break;
            }
        }
        if (headerIdx < 0 || headerIdx + 2 >= lines.Length) return;

        var header = lines[headerIdx];
        int idCol = header.IndexOf("Id", StringComparison.Ordinal);
        int versionCol = header.IndexOf("Version", StringComparison.OrdinalIgnoreCase);
        if (idCol < 0) return;

        // Data rows start after the separator line (headerIdx + 1)
        for (int i = headerIdx + 2; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length <= idCol) continue;

            var name = line[..idCol].Trim();
            int end = versionCol > idCol && line.Length > versionCol ? versionCol : line.Length;
            var id = line[idCol..end].Trim();

            // Winget IDs always contain a dot and no spaces (e.g. "7zip.7zip", "Google.Chrome")
            if (!string.IsNullOrWhiteSpace(name) && id.Contains('.') && !id.Contains(' '))
                map[name] = id;
        }
    }

    public async Task<string> UpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Update task {TaskId}: app={App} packageId={PackageId} productCode={ProductCode} sourceUrl={SourceUrl}",
            task.Id, task.AppName, task.PackageId, task.ProductCode, task.SourceUrl);

        if (!string.IsNullOrWhiteSpace(task.SourceUrl))
            return await InstallDownloadedPackageAsync(task, cancellationToken);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            var aptName = FirstSafeAptName(task.PackageId, task.ProductCode, task.AppName);
            if (string.IsNullOrWhiteSpace(aptName))
            {
                _logger.LogWarning("Task {TaskId} rejected: missing or unsafe apt package name", task.Id);
                return "Task rejected: missing or unsafe apt package name";
            }
            var (linuxCode, linuxOut) = await RunWithExitCodeAsync("apt-get",
                new[] { "install", "--only-upgrade", "-y", aptName }, cancellationToken);
            return linuxCode == 0 ? linuxOut : $"Task failed: apt-get exited {linuxCode}. {linuxOut}";
        }

        if (!IsWindows())
        {
            _logger.LogWarning("Task {TaskId} rejected: unsupported OS", task.Id);
            return "Task rejected: unsupported OS";
        }

        if (IsDotNetWorkloadComponent(task.AppName))
            return await RunDotNetWorkloadUpdateAsync(task, cancellationToken);

        var wingetResult = await RunWingetUpdateAsync(task, cancellationToken);
        if (!wingetResult.StartsWith("Task failed: no winget match", StringComparison.OrdinalIgnoreCase))
            return wingetResult;

        var componentResult = await TryRunWindowsComponentUpdateAsync(task, cancellationToken);
        return componentResult ?? wingetResult;
    }

    private async Task<string> RunWingetUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        var attempts = new List<WingetAttempt>();
        var packageId = SafePackageId(task.PackageId);
        if (packageId is not null)
            attempts.Add(new WingetAttempt($"--id {packageId}", ["--id", packageId, "--exact"]));

        if (!string.IsNullOrWhiteSpace(task.AppName))
        {
            attempts.Add(new WingetAttempt($"--name \"{task.AppName}\"", ["--name", task.AppName, "--exact"]));
            attempts.Add(new WingetAttempt($"query \"{task.AppName}\"", [task.AppName]));
        }

        if (attempts.Count == 0)
        {
            _logger.LogWarning("Task {TaskId} rejected: no usable winget id and no app name", task.Id);
            return "Task rejected: no usable winget package identifier";
        }

        var outputs = new List<string>();
        foreach (var attempt in attempts)
        {
            _logger.LogInformation("Running winget upgrade {Attempt} for task {TaskId}", attempt.Label, task.Id);
            var (code, output) = await RunWingetUpgradeAsync(attempt.Arguments, cancellationToken);
            if (code == 0) return output;
            if (IsAlreadyUpToDate(output)) return $"Already up to date: {output}";

            outputs.Add($"winget upgrade {attempt.Label} exited {code}: {output}");
            if (!IsWingetSelectionFailure(output))
                return $"Task failed: winget upgrade {attempt.Label} exited {code}. {output}";
        }

        return $"Task failed: no winget match could be upgraded. {string.Join(Environment.NewLine, outputs)}";
    }

    private Task<(int ExitCode, string Output)> RunWingetUpgradeAsync(string[] selectorArguments, CancellationToken cancellationToken)
    {
        var args = new List<string> { "upgrade" };
        args.AddRange(selectorArguments);
        args.AddRange([
            "--source",
            "winget",
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--disable-interactivity",
            "--silent",
        ]);
        return RunWithExitCodeAsync("winget", args.ToArray(), cancellationToken);
    }

    private static bool IsAlreadyUpToDate(string output) =>
        output.Contains("No applicable update found", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("No newer package versions are available", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("No available upgrade found", StringComparison.OrdinalIgnoreCase);

    private static bool IsWingetSelectionFailure(string output) =>
        output.Contains("No installed package found", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("No package found matching", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("No package found", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("Es wurde kein installiertes Paket gefunden", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("Es wurde kein Paket gefunden", StringComparison.OrdinalIgnoreCase);

    private async Task<string> InstallDownloadedPackageAsync(AgentTask task, CancellationToken cancellationToken)
    {
        if (!IsWindows())
        {
            _logger.LogWarning("Task {TaskId} rejected: downloaded packages only supported on Windows", task.Id);
            return "Task rejected: downloaded MSI packages are currently supported on Windows only";
        }
        if (string.IsNullOrWhiteSpace(task.Sha256))
        {
            _logger.LogWarning("Task {TaskId} rejected: missing package hash", task.Id);
            return "Task rejected: missing package hash";
        }

        // FIX #4: validate download URL against trusted host allowlist
        var downloadUrl = await ResolveTrustedDownloadUrlAsync(task.SourceUrl!, cancellationToken);
        if (downloadUrl is null)
        {
            _logger.LogError("Task {TaskId} rejected: SourceUrl '{Url}' is not in the trusted download hosts list", task.Id, task.SourceUrl);
            return "Task rejected: package source URL is not in the trusted hosts allowlist";
        }

        var args = string.IsNullOrWhiteSpace(task.InstallArgs) ? "/qn /norestart" : task.InstallArgs;
        if (!IsSafeMsiArgumentString(args))
        {
            _logger.LogWarning("Task {TaskId} rejected: install arguments '{Args}' not in allowlist", task.Id, args);
            return "Task rejected: install arguments are not allowlisted";
        }

        string path;
        try
        {
            path = await DownloadAndVerifyAsync(task, downloadUrl, cancellationToken);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "Task {TaskId} failed: download/hash verification error", task.Id);
            return $"Task failed: {ex.Message}";
        }

        try
        {
            _logger.LogInformation("Running msiexec for task {TaskId}, file={Path}, args={Args}", task.Id, path, args);
            // FIX #11: pass arguments as a list, not a single interpolated string
            var allArgs = new[] { "/i", path }.Concat(args.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToArray();
            var (code, output) = await RunWithExitCodeAsync("msiexec.exe", allArgs, cancellationToken);
            // msiexec returns 0 on success, 3010 = success-but-reboot-required
            if (code == 0 || code == 3010) return output;
            return $"Task failed: msiexec exited {code}. {output}";
        }
        finally
        {
            // FIX #16: always clean up the temp installer file
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                    _logger.LogDebug("Cleaned up temp installer {Path}", path);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to delete temp installer {Path}", path);
            }
        }
    }

    private async Task<string> DownloadAndVerifyAsync(AgentTask task, string downloadUrl, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Downloading package from {Url}", downloadUrl);
        var client = _httpClientFactory.CreateClient();
        var data = await client.GetByteArrayAsync(downloadUrl, cancellationToken);
        _logger.LogDebug("Downloaded {Bytes} bytes — verifying SHA-256", data.Length);

        var actual = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        if (!actual.Equals(task.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogError("Hash mismatch for task {TaskId}: expected={Expected} actual={Actual}", task.Id, task.Sha256, actual);
            throw new InvalidOperationException($"Package hash mismatch. Expected {task.Sha256}, got {actual}");
        }

        _logger.LogInformation("Package hash verified OK for task {TaskId}", task.Id);
        var path = Path.Combine(Path.GetTempPath(), $"1patch-{task.PackageArtifactId ?? task.Id}.msi");
        await File.WriteAllBytesAsync(path, data, cancellationToken);
        return path;
    }

    private async Task<string?> ResolveTrustedDownloadUrlAsync(string url, CancellationToken cancellationToken)
    {
        var resolved = ResolveDownloadUrl(url);
        if (!Uri.TryCreate(resolved, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            return null;

        var trustedOrigins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddTrustedOrigin(trustedOrigins, _options.ManagementUrl);
        foreach (var host in _options.TrustedDownloadHosts)
            AddTrustedOrigin(trustedOrigins, host);

        var node = await _nodes.GetBestNodeAsync(cancellationToken);
        if (node is not null)
            AddTrustedOrigin(trustedOrigins, node.PublicUrl);

        if (trustedOrigins.Count == 0)
        {
            _logger.LogWarning("No trusted download origins are configured or discoverable");
            return null;
        }

        return trustedOrigins.Contains(OriginOf(uri)) ? uri.ToString() : null;
    }

    private string ResolveDownloadUrl(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var absolute))
            return absolute.ToString();
        return $"{_options.ManagementUrl.TrimEnd('/')}/{url.TrimStart('/')}";
    }

    private static void AddTrustedOrigin(HashSet<string> origins, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        if (Uri.TryCreate(value.TrimEnd('/'), UriKind.Absolute, out var uri))
            origins.Add(OriginOf(uri));
    }

    private static string OriginOf(Uri uri) => uri.IsDefaultPort
        ? $"{uri.Scheme}://{uri.Host}"
        : $"{uri.Scheme}://{uri.Host}:{uri.Port}";

    private static string? SafePackageId(string? value)
    {
        var trimmed = value?.Trim();
        return !string.IsNullOrWhiteSpace(trimmed) && SafePackageIdPattern.IsMatch(trimmed) ? trimmed : null;
    }

    private static string? FirstSafeAptName(params string?[] values)
        => values.Select(v => v?.Trim())
            .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v) && SafeAptPackagePattern.IsMatch(v));

    private sealed record WingetAttempt(string Label, string[] Arguments);

    private async Task<string?> TryRunWindowsComponentUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        if (IsDotNetWorkloadComponent(task.AppName))
            return await RunDotNetWorkloadUpdateAsync(task, cancellationToken);

        if (IsVisualStudioOrWindowsSdkComponent(task.AppName))
            return await RunVisualStudioInstallerUpdateAsync(task, cancellationToken);

        return null;
    }

    private async Task<string> RunDotNetWorkloadUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Running dotnet workload update for task {TaskId} app={App}", task.Id, task.AppName);
        var (code, output) = await RunWithExitCodeAsync("dotnet", ["workload", "update"], cancellationToken);
        if (code == 0) return output;
        return $"Task failed: dotnet workload update exited {code}. {output}";
    }

    private async Task<string> RunVisualStudioInstallerUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        var installerDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Microsoft Visual Studio",
            "Installer");
        var vswhere = Path.Combine(installerDir, "vswhere.exe");
        var installer = Path.Combine(installerDir, "vs_installer.exe");

        if (!File.Exists(vswhere) || !File.Exists(installer))
        {
            return "Task failed: no winget match and Visual Studio Installer was not found for this SDK/component update";
        }

        var (listCode, listOutput) = await RunWithExitCodeAsync(vswhere, [
            "-all",
            "-products",
            "*",
            "-property",
            "installationPath"
        ], cancellationToken);
        if (listCode != 0)
            return $"Task failed: vswhere exited {listCode}. {listOutput}";

        var installPaths = listOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (installPaths.Length == 0)
            return "Task failed: no winget match and no Visual Studio installations were found for this SDK/component update";

        var outputs = new List<string>();
        foreach (var installPath in installPaths)
        {
            _logger.LogInformation("Running Visual Studio Installer update for {InstallPath}", installPath);
            var (code, output) = await RunWithExitCodeAsync(installer, [
                "update",
                "--installPath",
                installPath,
                "--quiet",
                "--norestart",
                "--wait"
            ], cancellationToken);
            outputs.Add($"Visual Studio Installer update for {installPath} exited {code}: {output}");
            if (code != 0 && code != 3010)
                return $"Task failed: Visual Studio Installer update exited {code}. {output}";
        }

        return string.Join(Environment.NewLine, outputs);
    }

    private static bool IsDotNetWorkloadComponent(string? appName)
    {
        if (string.IsNullOrWhiteSpace(appName)) return false;
        return appName.Contains("Microsoft.NET.Workload", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains(".NET Workload", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("DotNet Workload", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsVisualStudioOrWindowsSdkComponent(string? appName)
    {
        if (string.IsNullOrWhiteSpace(appName)) return false;
        return appName.Contains("Visual Studio", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Build Tools", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Windows SDK", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("WinRT Intellisense", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Universal CRT", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Application Verifier", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Windows Team Extension SDK", StringComparison.OrdinalIgnoreCase);
    }

    // FIX #17: split on all whitespace and trim each token
    private static bool IsSafeMsiArgumentString(string args)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "/qn", "/quiet", "/norestart", "ALLUSERS=1", "REBOOT=ReallySuppress"
        };
        return args.Split(Array.Empty<char>(), StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                   .All(allowed.Contains);
    }

    [SupportedOSPlatformGuard("windows")]
    private static bool IsWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    [SuppressMessage("Interoperability", "CA1416", Justification = "Called only after Windows OS check.")]
    private static List<InstalledApp> GetWindowsRegistryApps()
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
        var output = await RunAsync("dpkg-query",
            new[] { "-W", "-f=${Package}|${Version}|${Maintainer}\\n" },
            cancellationToken);
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('|'))
            .Where(parts => parts.Length >= 2)
            .Select(parts => new InstalledApp(parts[0], parts.Length > 2 ? parts[2] : "", parts[1], null, parts[0]))
            .ToList();
    }

    // FIX #11: accept string[] arguments so they are never shell-interpolated
    private static async Task<string> RunAsync(string fileName, string[] arguments, CancellationToken cancellationToken)
    {
        var (_, output) = await RunWithExitCodeAsync(fileName, arguments, cancellationToken);
        return output;
    }

    private static async Task<(int ExitCode, string Output)> RunWithExitCodeAsync(string fileName, string[] arguments, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        // Pass each argument individually — avoids any quoting/injection issues
        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Could not start {fileName}");

        var stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = await process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        var output = string.IsNullOrWhiteSpace(stderr) ? stdout : $"{stdout}\n{stderr}";
        return (process.ExitCode, output);
    }
}
