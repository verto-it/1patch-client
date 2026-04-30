# Package Execution Model

The client only executes tasks that map to built-in provider actions.

Allowed v1 actions:

- `refresh_inventory`
- `update_package`

Windows update execution uses winget package IDs. MSI library execution will require:

- SHA-256 verification before execution
- Optional Authenticode signature validation in a later hardening pass
- Allowlisted silent install arguments only
- Timeout and retry limits
- Result upload to the backend node
