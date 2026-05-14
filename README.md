# 1Patch Client

C# .NET 9 worker service for Windows and Linux. Enrolls with the management server, discovers backend nodes, sends heartbeats and inventory, and executes signed patch tasks.

**License:** AGPL-3.0-only

---

## Prerequisites

- .NET SDK 9.0+
- A running 1Patch Management Server with at least one backend node online
- A client enrollment token (created on the management server)
- Windows clients: install whichever managers you want 1Patch to use (`winget`, Chocolatey, or Scoop)
- Linux clients: Ubuntu/Debian-compatible host with `dpkg-query` and `apt-get`

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
    "TrustedSigningKeys": {
      "key_task_bundle_v1": {
        "keyId": "key_task_bundle_v1",
        "scope": "task_bundle",
        "status": "active",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----",
        "issuedAt": "2026-05-08T00:00:00.000Z",
        "isDev": false,
        "algorithm": "ES256"
      }
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

> `TrustedSigningKeys` pins scoped management public signing metadata. The dashboard-generated config includes every scope the client needs, including `bootstrap_manifest`, `task_bundle`, `task_ledger`, and `kill_switch`. The client rejects wildcard keys, dev keys outside development, unknown keys, revoked keys, expired retired keys, and signatures where the key scope does not match the envelope scope.

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
| `TrustedSigningKeys` | yes | — | Key ID to scoped P-256 public key metadata for management signatures |
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
- `TrustedSigningKeys`

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
                   └─ Execute via platform provider (winget / Chocolatey / Scoop / apt)
```

---

## Device Identity

On first run the client generates a unique device identity stored in `C:\ProgramData\1Patch\device.identity.json` (Windows) or the equivalent on Linux:

- **Device ID** — SHA-256 of hardware fingerprint (machine name, OS version, processor ID, motherboard serial, machine GUID)
- **EC P-256 key pair** — private key protected by DPAPI on Windows; stored at `/var/lib/1patch/device.identity.json` with `chmod 600` on Linux

The private key is never exposed through a public property or included in any log output.

---

## Package Execution Security

- Source URL must start with one of the configured `TrustedDownloadHosts`
- Bootstrap manifests, kill-switch state, task ledgers, and task bundles must carry valid ES256 signatures from pinned management keys scoped to the exact payload class
- SHA-256 hash is verified before execution
- Only allowlisted task types are executed (`update_package`, `refresh_inventory`)
- The client never executes arbitrary shell commands from the server

---

## Platform Support

| Platform | Inventory | Package execution |
|---|---|---|
| Windows | Registry, `winget list`, `choco list --limit-output`, Scoop app roots | `winget upgrade`, `choco upgrade`, `scoop update` |
| Linux | `dpkg-query` | `apt-get install --only-upgrade` |

Scoop packages installed under individual user profiles are reported in inventory with `packageScope: user`, but update tasks for those packages are rejected in this release. Global and service-account-visible Scoop installs can be updated.

Linux support in v1 is intentionally limited to repo-managed Ubuntu/Debian `apt` packages. Linux tasks must provide a safe `packageId` from inventory or an `apt` package artifact. Downloaded `.deb` packages, scripts, rpm/dnf, and zypper are not executed by the client yet.

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

Publish and install the client under `/opt/1patch`:

```bash
dotnet publish -c Release -r linux-x64 --self-contained -o ./publish/linux-x64
sudo mkdir -p /opt/1patch /var/lib/1patch
sudo cp -a ./publish/linux-x64/. /opt/1patch/
sudo cp appsettings.json /opt/1patch/appsettings.json
sudo chmod 700 /var/lib/1patch
```

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
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 1patch-client
```

The service must run as root for Linux package updates because `apt-get install --only-upgrade` requires elevated privileges. Inventory collection can run without root, but update tasks will be rejected until the service has package-manager privileges.
