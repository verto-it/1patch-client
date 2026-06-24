using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
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
    private readonly IPlatformInfo _platform;
    private readonly IProcessRunner _processRunner;

    // Package names are passed as ProcessStartInfo.ArgumentList entries, never through a shell.
    private static readonly Regex SafePackageIdPattern = new(@"^[A-Za-z0-9._\-]+$", RegexOptions.Compiled);
    private static readonly Regex SafeAptPackagePattern = new(@"^[a-z0-9][a-z0-9+.\-]*$", RegexOptions.Compiled);
    private static readonly Regex SafeFlatpakPackagePattern = new(@"^[A-Za-z0-9][A-Za-z0-9._\-]*$", RegexOptions.Compiled);

    public PlatformPackageProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<ClientOptions> options,
        NodeDiscoveryService nodes,
        IPlatformInfo platform,
        IProcessRunner processRunner,
        ILogger<PlatformPackageProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _nodes = nodes;
        _platform = platform;
        _processRunner = processRunner;
        _logger = logger;
    }

    public Task<IReadOnlyList<InstalledApp>> GetInstalledAppsAsync(CancellationToken cancellationToken)
    {
        if (_platform.IsWindows)
        {
            _logger.LogInformation("Enumerating installed Windows applications");
            return GetWindowsAppsAsync(cancellationToken);
        }
        if (_platform.IsLinux)
        {
            _logger.LogInformation("Enumerating installed Linux applications");
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
        if (wingetIds.Count > 0)
        {
            apps = apps
                .Select(a => wingetIds.TryGetValue(a.Name, out var id)
                    ? a with { PackageId = id, PackageManager = "winget", PackageScope = "system" }
                    : a)
                .ToList();
        }

        apps.AddRange(await TryGetChocolateyAppsAsync(cancellationToken));
        apps.AddRange(GetScoopApps());
        return apps;
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

    public static void ParseWingetListInto(string output, Dictionary<string, string> map)
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

    public static IReadOnlyList<InstalledApp> ParseChocolateyList(string output)
    {
        return output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split('|', 2, StringSplitOptions.TrimEntries))
            .Where(parts => parts.Length == 2 && SafePackageIdPattern.IsMatch(parts[0]))
            .Select(parts => new InstalledApp(parts[0], "Chocolatey", parts[1], null, parts[0], "chocolatey", "system"))
            .ToList();
    }

    private async Task<IReadOnlyList<InstalledApp>> TryGetChocolateyAppsAsync(CancellationToken cancellationToken)
    {
        try
        {
            var output = await RunAsync("choco", ["list", "--limit-output"], cancellationToken);
            var apps = ParseChocolateyList(output);
            _logger.LogInformation("Chocolatey inventory resolved {Count} package(s)", apps.Count);
            return apps;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Chocolatey inventory skipped because choco was unavailable or failed");
            return [];
        }
    }

    private IReadOnlyList<InstalledApp> GetScoopApps()
    {
        var roots = new List<(string AppsPath, string Scope)>();
        AddScoopRoot(roots, Path.Combine(_platform.CommonApplicationDataPath, "scoop", "apps"), "global");
        AddScoopRoot(roots, Path.Combine(Environment.GetEnvironmentVariable("SCOOP_GLOBAL") ?? "", "apps"), "global");
        AddScoopRoot(roots, Path.Combine(Environment.GetEnvironmentVariable("SCOOP") ?? "", "apps"), "system");

        var currentProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        AddScoopRoot(roots, Path.Combine(currentProfile, "scoop", "apps"), "system");

        var usersRoot = Directory.GetParent(currentProfile)?.FullName;
        if (!string.IsNullOrWhiteSpace(usersRoot) && Directory.Exists(usersRoot))
        {
            try
            {
                foreach (var profile in Directory.EnumerateDirectories(usersRoot))
                    AddScoopRoot(roots, Path.Combine(profile, "scoop", "apps"), "user");
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogDebug(ex, "Some user profile Scoop roots could not be scanned");
            }
            catch (IOException ex)
            {
                _logger.LogDebug(ex, "Some user profile Scoop roots could not be scanned");
            }
        }

        var apps = ScanScoopAppsFromRoots(roots);
        _logger.LogInformation("Scoop inventory resolved {Count} package(s)", apps.Count);
        return apps;
    }

    private static void AddScoopRoot(List<(string AppsPath, string Scope)> roots, string appsPath, string scope)
    {
        if (string.IsNullOrWhiteSpace(appsPath)) return;
        if (!Directory.Exists(appsPath)) return;
        if (roots.Any(root => string.Equals(Path.GetFullPath(root.AppsPath), Path.GetFullPath(appsPath), StringComparison.OrdinalIgnoreCase))) return;
        roots.Add((appsPath, scope));
    }

    public static IReadOnlyList<InstalledApp> ScanScoopAppsFromRoots(IEnumerable<(string AppsPath, string Scope)> roots)
    {
        var apps = new List<InstalledApp>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (appsPath, scope) in roots)
        {
            if (!Directory.Exists(appsPath)) continue;
            foreach (var appDir in SafeEnumerateDirectories(appsPath))
            {
                var packageId = Path.GetFileName(appDir);
                if (string.IsNullOrWhiteSpace(packageId) || !SafePackageIdPattern.IsMatch(packageId)) continue;
                if (!seen.Add($"{appsPath}|{packageId}")) continue;

                apps.Add(new InstalledApp(
                    packageId,
                    "Scoop",
                    GetScoopInstalledVersion(appDir),
                    null,
                    packageId,
                    "scoop",
                    scope));
            }
        }

        return apps;
    }

    private static IEnumerable<string> SafeEnumerateDirectories(string path)
    {
        try
        {
            return Directory.EnumerateDirectories(path).ToArray();
        }
        catch
        {
            return [];
        }
    }

    private static string GetScoopInstalledVersion(string appDir)
    {
        try
        {
            return Directory.EnumerateDirectories(appDir)
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name) && !string.Equals(name, "current", StringComparison.OrdinalIgnoreCase))
                .Order(StringComparer.OrdinalIgnoreCase)
                .LastOrDefault() ?? "0.0.0";
        }
        catch
        {
            return "0.0.0";
        }
    }

    public async Task<string> UpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Update task {TaskId}: app={App} packageId={PackageId} packageManager={PackageManager} packageScope={PackageScope} productCode={ProductCode} sourceUrl={SourceUrl}",
            task.Id, task.AppName, task.PackageId, task.PackageManager, task.PackageScope, task.ProductCode, task.SourceUrl);

        if (!string.IsNullOrWhiteSpace(task.SourceUrl))
            return await InstallDownloadedPackageAsync(task, cancellationToken);

        if (_platform.IsLinux)
        {
            return await RunLinuxPackageUpdateAsync(task, cancellationToken);
        }

        if (!_platform.IsWindows)
        {
            _logger.LogWarning("Task {TaskId} rejected: unsupported OS", task.Id);
            return "Task rejected: unsupported OS";
        }

        var packageManager = task.PackageManager?.Trim().ToLowerInvariant();
        if (packageManager == "chocolatey")
            return await RunChocolateyUpdateAsync(task, cancellationToken);
        if (packageManager == "scoop")
            return await RunScoopUpdateAsync(task, cancellationToken);
        if (!string.IsNullOrWhiteSpace(packageManager) && packageManager is not "winget" and not "msi")
            return $"Task rejected: unsupported Windows package manager '{task.PackageManager}'";

        // These component types are never in winget — skip straight to the right tool
        if (IsDotNetWorkloadComponent(task.AppName))
            return await RunDotNetWorkloadUpdateAsync(task, cancellationToken);

        if (IsVisualStudioOrWindowsSdkComponent(task.AppName))
            return await RunVisualStudioInstallerUpdateAsync(task, cancellationToken);

        // For everything else, try winget first, then fall back to component updaters
        var wingetResult = await RunWingetUpdateAsync(task, cancellationToken);
        if (!wingetResult.StartsWith("Task failed: no winget match", StringComparison.OrdinalIgnoreCase))
            return wingetResult;

        var componentResult = await TryRunWindowsComponentUpdateAsync(task, cancellationToken);
        return componentResult ?? wingetResult;
    }

    private async Task<string> RunChocolateyUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        var packageId = SafePackageId(task.PackageId);
        if (packageId is null)
            return "Task rejected: missing or unsafe Chocolatey package identifier";

        try
        {
            _logger.LogInformation("Running Chocolatey upgrade for task {TaskId} package={PackageId}", task.Id, packageId);
            var result = await RunWithExitCodeAsync("choco", ["upgrade", packageId, "-y", "--limit-output"], cancellationToken);
            if (result.ExitCode is 0 or 3010 or 1641) return result.Output;
            if (result.ExitCode == 2 || IsAlreadyUpToDate(result.Output)) return $"Already up to date: {result.Output}";
            if (IsChocolateySelectionFailure(result.Output)) return $"Task failed: no Chocolatey match could be upgraded. {result.Output}";
            return $"Task failed: choco upgrade exited {result.ExitCode}. {result.Output}";
        }
        catch (Win32Exception ex)
        {
            _logger.LogWarning(ex, "Chocolatey executable was not found for task {TaskId}", task.Id);
            return "Task rejected: Chocolatey executable was not found on this device";
        }
    }

    private async Task<string> RunScoopUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        if (string.Equals(task.PackageScope, "user", StringComparison.OrdinalIgnoreCase))
            return "Task rejected: per-user Scoop packages are inventory-only in this release";

        var packageId = SafePackageId(task.PackageId);
        if (packageId is null)
            return "Task rejected: missing or unsafe Scoop package identifier";

        var args = new List<string> { "update", packageId };
        if (string.Equals(task.PackageScope, "global", StringComparison.OrdinalIgnoreCase))
            args.Add("--global");

        try
        {
            _logger.LogInformation("Running Scoop update for task {TaskId} package={PackageId} scope={Scope}", task.Id, packageId, task.PackageScope ?? "system");
            var result = await RunWithExitCodeAsync("scoop", args.ToArray(), cancellationToken);
            if (result.ExitCode == 0) return result.Output;
            if (IsScoopNoOp(result.Output)) return $"Already up to date: {result.Output}";
            if (IsScoopSelectionFailure(result.Output)) return $"Task failed: no Scoop match could be upgraded. {result.Output}";
            return $"Task failed: scoop update exited {result.ExitCode}. {result.Output}";
        }
        catch (Win32Exception ex)
        {
            _logger.LogWarning(ex, "Scoop executable was not found for task {TaskId}", task.Id);
            return "Task rejected: Scoop executable was not found on this device";
        }
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

    private Task<ProcessResult> RunWingetUpgradeAsync(string[] selectorArguments, CancellationToken cancellationToken)
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

    private static bool IsChocolateySelectionFailure(string output) =>
        output.Contains("not installed", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("Unable to find", StringComparison.OrdinalIgnoreCase);

    private static bool IsScoopNoOp(string output) =>
        output.Contains("Latest versions for all apps are installed", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("is already up-to-date", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("No updates available", StringComparison.OrdinalIgnoreCase);

    private static bool IsScoopSelectionFailure(string output) =>
        output.Contains("Couldn't find manifest", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("isn't installed", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("is not installed", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("No app matches", StringComparison.OrdinalIgnoreCase);

    private async Task<string> RunLinuxPackageUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        if (!_platform.IsLinuxRoot)
            return "Task rejected: Linux package updates require the client service to run as root";

        var packageManager = task.PackageManager?.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(packageManager)) packageManager = "apt";

        return packageManager switch
        {
            "apt" => await RunAptUpdateAsync(task, cancellationToken),
            "snap" => await RunSnapUpdateAsync(task, cancellationToken),
            "flatpak" => await RunFlatpakUpdateAsync(task, cancellationToken),
            _ => $"Task rejected: unsupported Linux package manager '{task.PackageManager}'"
        };
    }

    private async Task<string> RunAptUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        var packageId = FirstSafeAptName(task.PackageId);
        if (string.IsNullOrWhiteSpace(packageId))
        {
            _logger.LogWarning("Task {TaskId} rejected: missing or unsafe apt package name", task.Id);
            return "Task rejected: missing or unsafe apt package name";
        }

        try
        {
            var result = await RunWithExitCodeAsync("apt-get",
                ["install", "--only-upgrade", "-y", packageId],
                new Dictionary<string, string> { ["DEBIAN_FRONTEND"] = "noninteractive" },
                cancellationToken);
            return result.ExitCode == 0 ? result.Output : $"Task failed: apt-get exited {result.ExitCode}. {result.Output}";
        }
        catch (Win32Exception ex)
        {
            _logger.LogWarning(ex, "Task {TaskId} failed: apt-get was not found", task.Id);
            return "Task failed: apt-get was not found; Linux apt support requires an Ubuntu/Debian-compatible host";
        }
    }

    private async Task<string> RunSnapUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        var packageId = FirstSafeAptName(task.PackageId);
        if (string.IsNullOrWhiteSpace(packageId))
            return "Task rejected: missing or unsafe Snap package name";

        try
        {
            var result = await RunWithExitCodeAsync("snap", ["refresh", packageId], cancellationToken);
            if (result.ExitCode == 0) return result.Output;
            if (result.Output.Contains("has no updates available", StringComparison.OrdinalIgnoreCase))
                return $"Already up to date: {result.Output}";
            return $"Task failed: snap refresh exited {result.ExitCode}. {result.Output}";
        }
        catch (Win32Exception ex)
        {
            _logger.LogWarning(ex, "Task {TaskId} failed: snap was not found", task.Id);
            return "Task rejected: snap executable was not found on this device";
        }
    }

    private async Task<string> RunFlatpakUpdateAsync(AgentTask task, CancellationToken cancellationToken)
    {
        var packageId = SafeFlatpakPackageId(task.PackageId);
        if (packageId is null)
            return "Task rejected: missing or unsafe Flatpak application id";

        try
        {
            var result = await RunWithExitCodeAsync("flatpak", ["update", "-y", packageId], cancellationToken);
            if (result.ExitCode == 0) return result.Output;
            if (result.Output.Contains("Nothing to do", StringComparison.OrdinalIgnoreCase))
                return $"Already up to date: {result.Output}";
            return $"Task failed: flatpak update exited {result.ExitCode}. {result.Output}";
        }
        catch (Win32Exception ex)
        {
            _logger.LogWarning(ex, "Task {TaskId} failed: flatpak was not found", task.Id);
            return "Task rejected: flatpak executable was not found on this device";
        }
    }

    private async Task<string> InstallDownloadedPackageAsync(AgentTask task, CancellationToken cancellationToken)
    {
        if (!_platform.IsWindows)
        {
            _logger.LogWarning("Task {TaskId} rejected: downloaded packages only supported on Windows", task.Id);
            return "Task rejected: downloaded package artifacts are currently supported on Windows only";
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

        var packageManager = task.PackageManager?.Trim().ToLowerInvariant();
        var isExe = packageManager == "exe";
        var args = string.IsNullOrWhiteSpace(task.InstallArgs)
            ? isExe ? "/quiet /norestart" : "/qn /norestart"
            : task.InstallArgs;
        if (!IsSafeInstallerArgumentString(args, isExe))
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
            var argList = TokenizeInstallerArgs(args);
            var (code, output) = isExe
                ? await RunWithExitCodeAsync(path, argList, cancellationToken)
                : await RunWithExitCodeAsync("msiexec.exe", new[] { "/i", path }.Concat(argList).ToArray(), cancellationToken);
            _logger.LogInformation("Installer finished for task {TaskId}, file={Path}, code={Code}", task.Id, path, code);
            if (code == 0 || code == 3010) return output;
            if (code == 1641) return output;
            return $"Task failed: installer exited {code}. {output}";
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
        var ext = string.Equals(task.PackageManager, "exe", StringComparison.OrdinalIgnoreCase) ? ".exe" : ".msi";
        var path = Path.Combine(Path.GetTempPath(), $"1patch-{task.PackageArtifactId ?? task.Id}{ext}");
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

    private static string? SafeFlatpakPackageId(string? value)
    {
        var trimmed = value?.Trim();
        return !string.IsNullOrWhiteSpace(trimmed) && trimmed.Contains('.') && SafeFlatpakPackagePattern.IsMatch(trimmed) ? trimmed : null;
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
                "--norestart"
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
               appName.Contains("DotNet Workload", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Microsoft.NET.Sdk.", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Microsoft.NET.Runtime.", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Microsoft.NET.Component.", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains(".NET.Sdk.", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains(".NET.Runtime.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsVisualStudioOrWindowsSdkComponent(string? appName)
    {
        if (string.IsNullOrWhiteSpace(appName)) return false;
        return appName.Contains("Visual Studio", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Build Tools", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Windows SDK", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("WinRT", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Intellisense", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Windows IoT", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Extension SDK", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Universal CRT", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Application Verifier", StringComparison.OrdinalIgnoreCase) ||
               appName.Contains("Windows Team Extension SDK", StringComparison.OrdinalIgnoreCase);
    }

    // FIX #17: split on all whitespace and trim each token
    private static bool IsSafeInstallerArgumentString(string args, bool allowExeStyleArgs)
    {
        var allowedMsi = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "/qn", "/quiet", "/norestart", "ALLUSERS=1", "REBOOT=ReallySuppress"
        };
        var tokens = TokenizeInstallerArgs(args);
        if (!allowExeStyleArgs) return tokens.All(allowedMsi.Contains);

        var allowedExe = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "/S", "/silent", "/verysilent", "/quiet", "/qn", "/norestart",
            "--silent", "--quiet", "--norestart", "--accept-license", "--accept-package-agreements",
            "-s", "-q", "-y"
        };
        return tokens.All(token =>
            allowedExe.Contains(token) ||
            Regex.IsMatch(token, @"^[A-Za-z][A-Za-z0-9_.-]{0,40}=(?:[A-Za-z0-9_.:@%+\-\\ ]{0,120})$"));
    }

    private static string[] TokenizeInstallerArgs(string args)
    {
        var matches = Regex.Matches(args, @""".+?""|\S+");
        return matches
            .Select(m => m.Value.Trim().Trim('"'))
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToArray();
    }

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

    private async Task<IReadOnlyList<InstalledApp>> GetLinuxAppsAsync(CancellationToken cancellationToken)
    {
        string output;
        try
        {
            output = await RunAsync("dpkg-query",
                new[] { "-W", "-f=${Package}|${Version}|${Maintainer}\\n" },
                cancellationToken);
        }
        catch (Win32Exception ex)
        {
            throw new InvalidOperationException("Linux inventory requires dpkg-query; this host does not look like an Ubuntu/Debian-compatible system", ex);
        }
        var apps = new List<InstalledApp>();
        apps.AddRange(ParseDpkgQueryOutput(output));
        apps.AddRange(await TryGetSnapAppsAsync(cancellationToken));
        apps.AddRange(await TryGetFlatpakAppsAsync(cancellationToken));
        return apps;
    }

    public static IReadOnlyList<InstalledApp> ParseDpkgQueryOutput(string output)
    {
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('|'))
            .Where(parts => parts.Length >= 2)
            .Select(parts => new InstalledApp(parts[0], parts.Length > 2 ? parts[2] : "", parts[1], null, parts[0], "apt", "system"))
            .ToList();
    }

    public static IReadOnlyList<InstalledApp> ParseSnapListOutput(string output)
    {
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Skip(1)
            .Select(line => Regex.Split(line, @"\s+"))
            .Where(parts => parts.Length >= 2 && SafeAptPackagePattern.IsMatch(parts[0]))
            .Select(parts => new InstalledApp(parts[0], "Snap", parts[1], null, parts[0], "snap", "system"))
            .ToList();
    }

    public static IReadOnlyList<InstalledApp> ParseFlatpakListOutput(string output)
    {
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split('\t'))
            .Where(parts => parts.Length >= 3 && SafeFlatpakPackageId(parts[1]) is not null)
            .Select(parts => new InstalledApp(parts[0], "Flatpak", parts[2], null, parts[1], "flatpak", "system"))
            .ToList();
    }

    private async Task<IReadOnlyList<InstalledApp>> TryGetSnapAppsAsync(CancellationToken cancellationToken)
    {
        try
        {
            var output = await RunAsync("snap", ["list"], cancellationToken);
            var apps = ParseSnapListOutput(output);
            _logger.LogInformation("Snap inventory resolved {Count} package(s)", apps.Count);
            return apps;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Snap inventory skipped because snap was unavailable or failed");
            return [];
        }
    }

    private async Task<IReadOnlyList<InstalledApp>> TryGetFlatpakAppsAsync(CancellationToken cancellationToken)
    {
        try
        {
            var output = await RunAsync("flatpak", ["list", "--app", "--columns=name,application,version"], cancellationToken);
            var apps = ParseFlatpakListOutput(output);
            _logger.LogInformation("Flatpak inventory resolved {Count} package(s)", apps.Count);
            return apps;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Flatpak inventory skipped because flatpak was unavailable or failed");
            return [];
        }
    }

    // FIX #11: accept string[] arguments so they are never shell-interpolated
    private async Task<string> RunAsync(string fileName, string[] arguments, CancellationToken cancellationToken)
    {
        var result = await RunWithExitCodeAsync(fileName, arguments, cancellationToken);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"{fileName} exited {result.ExitCode}. {result.Output}");
        return result.Output;
    }

    private Task<ProcessResult> RunWithExitCodeAsync(string fileName, string[] arguments, CancellationToken cancellationToken)
        => RunWithExitCodeAsync(fileName, arguments, null, cancellationToken);

    private Task<ProcessResult> RunWithExitCodeAsync(
        string fileName,
        string[] arguments,
        IReadOnlyDictionary<string, string>? environment,
        CancellationToken cancellationToken)
    {
        return _processRunner.RunAsync(fileName, arguments, environment, cancellationToken);
    }
}
