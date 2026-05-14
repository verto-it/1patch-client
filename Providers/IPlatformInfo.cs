using System.Runtime.InteropServices;

namespace OnePatch.Client.Providers;

public interface IPlatformInfo
{
    bool IsWindows { get; }
    bool IsLinux { get; }
    bool IsLinuxRoot { get; }
    string CommonApplicationDataPath { get; }
}

public sealed class SystemPlatformInfo : IPlatformInfo
{
    public bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
    public bool IsLinux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
    public bool IsLinuxRoot => IsLinux && string.Equals(Environment.UserName, "root", StringComparison.Ordinal);
    public string CommonApplicationDataPath => Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
}
