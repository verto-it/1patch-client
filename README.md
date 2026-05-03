# 1Patch Client

C# .NET 8 worker service for Windows and Linux. Enrolls with the management server, discovers backend nodes, sends heartbeats and inventory, and executes signed patch tasks.

**License:** AGPL-3.0-only

---

## Prerequisites

- .NET SDK 8.0+
- A running 1Patch Management Server with at least one backend node online
- A client enrollment token (created on the management server)

---

## First-Time Setup

### 1. Create a client enrollment on the management server

```powershell
$enrollment = Invoke-RestMethod `
  -Method Post "https://manage.1patch.local:4100/devices/enrollments" `
  -Headers @{ "Authorization" = "Bearer <admin-jwt>" } `
  -ContentType "application/json" `
  -Body '{ "tenantId": "default", "mode": "batch", "maxUses": 100 }'

$enrollment.enrollmentToken  # copy this
```

### 2. Configure appsettings.json

Edit `appsettings.json` on each client machine:

```json
{
  "OnePatch": {
    "TenantId": "default",
    "ManagementUrl": "https://manage.1patch.local:4100",
    "EnrollmentToken": "<enrollmentToken from step 1>",
    "TrustedSigningPublicKeys": {
      "main": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
    },
    "TrustedDownloadHosts": [
      "https://manage.1patch.local:4100"
    ],
    "ClientName": "",
    "HeartbeatSeconds": 60,
    "InventoryMinutes": 30,
    "NodeProbeTimeoutMilliseconds": 2000
  }
}
```

> `TrustedSigningPublicKeys` pins the management public signing keys. The client rejects bootstrap manifests and task bundles signed by unknown keys.

### 3. Build and run

**Development:**
```powershell
cd 1patch-client
dotnet restore
dotnet run
```

**Production (self-contained, Windows x64):**
```powershell
dotnet publish -c Release -r win-x64 --self-contained -o ./publish/win-x64
./publish/win-x64/1patch-client.exe
```

**Production (self-contained, Linux x64):**
```bash
dotnet publish -c Release -r linux-x64 --self-contained -o ./publish/linux-x64
./publish/linux-x64/1patch-client
```

---

## Configuration Reference

| Key | Required | Default | Description |
|---|---|---|---|
| `TenantId` | yes | `default` | Tenant identifier — must match the enrollment |
| `ManagementUrl` | yes | — | Base URL of the management server |
| `EnrollmentToken` | yes | — | Token issued by the management server |
| `TrustedSigningPublicKeys` | yes | — | Key ID to P-256 public key PEM map for management signatures |
| `TrustedDownloadHosts` | yes | — | Allowlist of HTTPS origins for package downloads |
| `ClientName` | no | machine hostname | Override the display name for this device |
| `HeartbeatSeconds` | no | `60` | How often to send a heartbeat to the backend node |
| `InventoryMinutes` | no | `30` | How often to upload the installed-app inventory |
| `NodeProbeTimeoutMilliseconds` | no | `2000` | Timeout when probing backend nodes for reachability |

---

## Startup Checks

The client exits immediately with a fatal error if any of the following are missing:
- `ManagementUrl`
- `EnrollmentToken`
- `TrustedSigningPublicKeys`

---

## Worker Lifecycle

```
Start
  │
  ├─ Load / generate device identity (EC P-256 key pair, hardware-bound ID)
  ├─ Discover backend nodes (GET /agent/bootstrap/:tenantId — signature verified)
  ├─ Probe nodes for reachability, pick the best one
  ├─ Register device with node (POST /agent/register)
  │
  └─ Loop every tick:
       ├─ Heartbeat         (every HeartbeatSeconds)
       ├─ Inventory upload  (every InventoryMinutes)
       └─ Task poll         (every HeartbeatSeconds)
              └─ For each pending task:
                   ├─ Verify signed task bundle and expiry
                   ├─ Verify task source URL is in TrustedDownloadHosts
                   ├─ Download package
                   ├─ Verify SHA-256 hash
                   └─ Execute via platform provider (winget / apt)
```

---

## Device Identity

On first run the client generates a unique device identity stored in `C:\ProgramData\1Patch\device.identity.json` (Windows) or the equivalent on Linux:

- **Device ID** — SHA-256 of hardware fingerprint (machine name, OS version, processor ID, motherboard serial, machine GUID)
- **EC P-256 key pair** — private key protected by DPAPI on Windows; file is `chmod 600` on Linux

The private key is never exposed through a public property or included in any log output.

---

## Package Execution Security

- Source URL must start with one of the configured `TrustedDownloadHosts`
- Bootstrap manifests and task bundles must carry valid ES256 signatures from a pinned management key
- SHA-256 hash is verified before execution
- Only allowlisted task types are executed (`update_package`, `refresh_inventory`)
- The client never executes arbitrary shell commands from the server

---

## Platform Support

| Platform | Inventory | Package execution |
|---|---|---|
| Windows | Registry (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`) | `winget upgrade` |
| Linux | `dpkg -l` | `apt-get install` |

---

## Installing as a Windows Service

```powershell
# Publish first, then:
New-Service `
  -Name "1PatchClient" `
  -BinaryPathName "C:\Program Files\1Patch\1patch-client.exe" `
  -DisplayName "1Patch Client" `
  -StartupType Automatic

Start-Service 1PatchClient
```

---

## Installing as a Linux systemd Service

```ini
# /etc/systemd/system/1patch-client.service
[Unit]
Description=1Patch Client
After=network-online.target

[Service]
ExecStart=/opt/1patch/1patch-client
WorkingDirectory=/opt/1patch
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now 1patch-client
```
