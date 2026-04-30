# 1Patch Client

C# worker service for Windows and Linux. The client enrolls, probes backend nodes, sends heartbeats and inventory, and executes allowlisted patch tasks.

## Quick Start

```powershell
dotnet restore
dotnet run
```

## Providers

- Windows: registry inventory and winget update execution.
- Linux: dpkg/apt inventory and upgrade execution skeleton.

Server tasks must map to known provider actions. The client does not execute arbitrary commands from the management server or backend nodes.
