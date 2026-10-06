# Quality and security guarantees

This document summarizes stable product guarantees for SBfleet 1.x. It is written for operators and contributors reviewing the finished product, not internal run ledgers.

## Test layers

| Layer | Purpose |
| --- | --- |
| Unit | Pure logic, contracts, redaction, registry edge cases |
| Process | CLI subprocess behavior, exit codes, JSON contracts |
| Integration | Docker compose contracts, nginx fixtures, ownership |
| Acceptance | End-to-end disposable fixtures (multi-project, backup, sandbox, update) |

See [TESTING_STRATEGY.md](TESTING_STRATEGY.md) for gate commands.

## Multi-project isolation

Two simultaneous official projects must keep distinct Compose identities, secrets, ports, storage, and lifecycle. Tests cover cross-read refusal, independent stop/restart, and remove survival of sibling projects.

## Destructive authority

Mutations require project identity, locks, and ownership proof. SBfleet refuses Docker cleanup by name resemblance, arbitrary prune operations, and unproven resource deletion.

## Recovery

Backup success requires more than archive existence. Restore paths verify encrypted archives and recovery contracts before mutating live project data.

## Local sandbox

Official Supabase CLI sandboxes are separate from fleet projects. The wrapper blocks Cloud login/link flows and remote destructive targets by default.

## Security boundary

- **Trusted local operator** on their machine
- **Not** hostile same-user isolation
- **No** Supabase Cloud authority unless the operator configures external integrations themselves

See [SECRETS_AND_SECURITY.md](SECRETS_AND_SECURITY.md) and [SECURITY.md](../SECURITY.md) for reporting and secret handling.
