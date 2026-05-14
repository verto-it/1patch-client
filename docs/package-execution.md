# Package Execution Model

The client only executes tasks that map to built-in provider actions.

Allowed v1 actions:

- `refresh_inventory`
- `update_package`

Windows update execution uses explicit, signed package-manager metadata:

- `winget` tasks run `winget upgrade`
- `chocolatey` tasks run `choco upgrade <packageId> -y --limit-output`
- `scoop` tasks run `scoop update <packageId>` for service-account-visible installs and `--global` for global installs

Per-user Scoop packages are reported in inventory but rejected for execution in this release. MSI library execution requires:

- SHA-256 verification before execution
- Optional Authenticode signature validation in a later hardening pass
- Allowlisted silent install arguments only
- Timeout and retry limits
- Result upload to the backend node
