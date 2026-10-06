# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting a vulnerability

Please report security issues through **GitHub Security Advisories** on the public SBfleet repository once it is published. Do not open public issues for undisclosed vulnerabilities.

If GitHub advisories are unavailable, contact the repository maintainers through the channel listed in the public repository profile.

Please include steps to reproduce, affected versions, and impact. We ask that you do not publish details until we have had a reasonable chance to review and coordinate a fix.

## Security boundary

SBfleet is designed for a **trusted local operator** on a machine they control:

- It is **not** a multi-tenant security boundary against a hostile same-user adversary.
- It does **not** grant Supabase Cloud authority by default.
- Fleet projects bind services to loopback unless the operator explicitly configures public hostnames and nginx/TLS separately.

Secrets live in project `.env` files and encrypted backups. SBfleet redacts diagnostics where possible, but operators remain responsible for filesystem permissions and backup key handling.

## Third-party software

SBfleet downloads and invokes pinned third-party tools (Supabase CLI, age). Those components are governed by their own licenses and security posture. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
