# Changelog

All notable changes to SBfleet are documented here.

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
