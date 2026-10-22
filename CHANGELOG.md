# Changelog

All notable changes to SBfleet are documented here.

## 1.1.0 — Release candidate

Feature release prepared for publication. The current public release remains v1.0.1.

### Fleet observability

- Read-only fleet dashboard with project health, backup and service visibility.
- Machine-readable `status --all --json` using a versioned fleet snapshot.
- Responsive terminal panels, labelled connections, clear attention reasons,
  project details, help and predictable keyboard/quit behavior.

### Agent integration

- Local stdio, read-only MCP with fleet, status, connection, backup, doctor-summary
  and schema tools. No remote listener, credential reveal or mutation tools.

### Project cloning

- Verified same-pin clone with fresh project identity, ports and paths.
- Destination pooler rebinding and preservation of the source's prior runtime state.
- Verified targets end STOPPED. Required recovery credentials remain shared;
  cloning does not rotate secrets or support cross-version cloning or rollback.

### Schema planning

- Read-only schema diff and migration planning for the reviewed same pin.
- Classification as SAFE, REVIEW_REQUIRED, DESTRUCTIVE or UNSUPPORTED.
- No automatic migration execution, SQL preview or `migrate apply`.

## 1.0.1 — 2026-10-18

Patch release focused on reliability and safety checks; no new product features.

### Fixed

- Strengthened Docker/live-resource identity checks before lifecycle mutations and cleanup.
- Hardened configured-secret redaction across diagnostic and error output.
- Corrected interrupted-update continuation while retaining the original operation, reviewed target, and recovery evidence.
- Improved backup cleanup failure reporting, preserving valid encrypted archives and identifying residual staging paths.
- Made deletion safety fail closed when mount information cannot establish a safe cleanup boundary.
- Tightened test-resource cleanup to exact owned Docker resources and expanded reliability regression coverage.

### Documentation

- Refreshed the public README with verified command examples, installer-managed sandbox tooling, and the bounded backup/recovery contract.

Fresh installation, reinstall, uninstall/reinstall, and the 1.0.0 → 1.0.1 upgrade path were verified. Production installation validation passed without managed project or registry mutation. Existing same-pin restore,
reviewed-update, and trusted-local-user boundaries remain unchanged.

## [1.0.0] — 2026-10-05

First public release of SBfleet: a local control plane for self-hosted Supabase stacks on one Linux host.

### Added

- Filesystem-backed project registry with guarded create, start, stop, restart, and remove lifecycle
- Original Supabase Studio access per project gateway
- Recovery-verified encrypted backup and same-pin restore
- Pinned official self-hosted stack materialization and compatible update workflow
- Disposable official Supabase CLI sandbox, isolated from fleet projects
- Interactive shell with slash commands and session project selection
- `configure` for human-facing display names without changing the immutable project slug
- `connection`, `env`, `secrets`, `doctor`, and nginx template generation helpers
- User installer (`scripts/install-user.sh`) with pinned Supabase CLI and age tooling

### Security model

- Loopback-only publish by default; trusted local operator; not hostile same-user isolation
- No Supabase Cloud login or link in the sandbox wrapper

[1.0.0]: https://github.com/Pepinko81/sbfleet/releases/tag/v1.0.0
