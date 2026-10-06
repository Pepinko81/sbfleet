# Operator workflows

This is a V1 contract, not proof commands exist in the planning baseline.

## Install and preflight

Use Linux **amd64/arm64**, Python 3.10+ (`venv`), local Engine 28+, Compose `!override` support, Git, sh/coreutils, jq, OpenSSL, Node≥16.

**Operator install (production):** `bash scripts/install-user.sh` performs a transactional user-level install into `~/.local/lib/sbfleet/` with the active generation linked as `current/` (non-editable package) and creates **only** `~/.local/bin/sbfleet`. Managed tools (age **1.3.2**, Supabase CLI **2.118.0**) live under the active `current/` generation and are invoked by absolute path — SBfleet does **not** create `~/.local/bin/age` or `~/.local/bin/supabase` by default. Pins/SHA256: `packaging/tool-pins.toml`. Artifact verification uses `env -i … PATH=…:$HOME/.local/bin /bin/sh -c 'command -v sbfleet && …'`. The installer also probes the **operator’s inherited PATH** (current shell) and, when practical, a login shell; it cannot mutate an already-open parent shell. **FULL V1 READY** requires artifact planes (SBFLEET CLI / DOCKER / BACKUP / SANDBOX) **and** current-shell resolution of `sbfleet`; otherwise it reports `INSTALLATION ARTIFACTS READY` / `CURRENT SHELL sbfleet: PENDING` with `export PATH="$HOME/.local/bin:$PATH"` (exit 4). `--configure-path` remains opt-in. Upgrade: re-run the installer (stage → verify → promote). Uninstall: `bash scripts/uninstall-user.sh` (containment-checked; never deletes fleet data).

**Development / gates:** `bash scripts/ensure-dev-env.sh` (editable checkout `.venv`). PATH fallback for age/supabase is only for unmanaged/dev installs (`SBFLEET_ALLOW_PATH_TOOLS=1` or no managed prefix); `/node_modules/` binaries are always refused.

`sbfleet doctor` diagnoses Docker/daemon/Compose, Node, disk, host-level managed age/CLI hints, optional nginx, and project/sandbox checks. No root required once Docker access exists; never run automatic sudo installation. Data root (`~/.local/share/sbfleet`) is XDG-compatible and independent of the software prefix and source checkout.

Provision backup encryption before relying on a project: create a private age identity outside source/data root (`age-keygen`), back it up offline, put its public recipient in mode-0600 fleet.json `backup_recipients` / `age_recipients` array, and run a test backup/restore. Do not store the only recovery identity on the server being backed up. age is an external executable (managed by the installer), not a Python dependency.

### Application connectivity

- **Host applications (supported):** use `sbfleet connection PROJECT` for allocated loopback host ports. Container-internal Postgres is **5432**; the host port is the project’s `db_direct` (never assume host 5432). Prefer `sbfleet env PROJECT --admin -- COMMAND` for migrations. Restart preserves assigned ports.
- **Applications in other Docker containers:** **not supported in V1** (loopback-only publish; no shared application network). See follow-up *Dockerized Application ↔ SBfleet Project Connectivity*.
- **Remote PostgreSQL:** **not supported by default**. Do not bind Postgres publicly.

## First project

```sh
sbfleet create myapp --start --yes
sbfleet projects
sbfleet status myapp
sbfleet studio myapp
# Studio uses HTTP Basic Auth. Username is printed by create/status/studio.
# Reveal only Studio credentials (not the full .env):
sbfleet secrets myapp --reveal --keys DASHBOARD_USERNAME,DASHBOARD_PASSWORD
```

Only reveal when intentionally retrieving Studio credentials. Changing `DASHBOARD_*` in `.env` requires a guarded stop then start (container recreate); plain `restart` does not refresh container environment.

**Change Studio / fleet display names** with `sbfleet configure PROJECT` (optional `--name`, `--organization-name`, `--studio-project`). This updates CONFIGURED metadata and allowlisted `STUDIO_DEFAULT_*` keys only — it does **not** rename the SBfleet slug, UUID, Compose project, ports, or secrets. If the stack is running, Studio Env stays stale until `sbfleet stop PROJECT && sbfleet start PROJECT`. `configure` without flags shows CONFIGURED vs APPLIED and any meta↔env drift. Do not hand-edit `.env` for ordinary presentation settings.

Configure real SMTP/phone/OAuth before enabling signup; default create disables signup delivery that cannot work securely. Studio admin Auth and database APIs remain available. No DNS required. Optional `--domain` stores metadata only; generate an nginx template with `nginx generate` (see STUDIO_AND_NGINX). Over SSH, loopback URLs refer to the server — operators must arrange their own port-forward; sbfleet does not automate SSH or remote Studio access.

## Daily operations

`start`, `stop` and `restart` target an explicit project. Stop preserves data. `logs myapp auth --tail 100` is finite; add --follow to tail. `connection` prints nonsecret addresses. `env myapp --admin -- bun run db:migrate` is explicit real-project admin authority, not an agent sandbox command. Supply --credentials-file for an app-owned runtime role. Application migration tools remain the app's choice.

`doctor myapp` reuses shared read-only validators: project identity, secret-file mode/owner/nlink, vendor integrity, **production effective Compose contract** (`build_project_contract` + `_validate_effective_compose` — never PASS a reduced contract when the vendor image map is unavailable), live ownership invent (including recorded image IDs when present), unresolved journal policy, currently usable recovery archive (receipt alone is insufficient), health lifecycle, plus **CURRENT** runtime image inspect facts vs **RECORDED** `image_digests` metadata (explicitly labeled; container count alone is never called an image inspection). Host-only doctor checks Docker/tools/disk. Each check has an explicit criticality class; exit priority is safety > prerequisite > unhealthy; informational UNKNOWN alone does not force nonzero. Expensive disk sizes may be unknown; don't recurse multi-GB data on each status. No doctor --fix side effects. Mutation authority invents ownership before start/stop/restart/remove and backup/restore/update preparation.

## Backup and restore

```sh
sbfleet backup myapp --identity /secure/backup.agekey
sbfleet restore myapp /path/to/archive.tar.age --yes --identity /secure/backup.agekey
```

Backup has downtime and encrypts secrets with age. prior hardening work. Decrypt/structural checks remain weaker levels and do not authorize `remove`/`update`. Same-project restore validates the internal manifest, creates a recovery-verified pre-restore backup, journals quarantine/swap, reconciles destination placement (never blind `.env`/`project.json` replacement), and prints RESTORED only after destination HEALTHY. Age decrypt is not cryptographic source provenance. `--recover` remains unsupported. Copy ciphertext plus receipt off-host. Backup scheduling/retention remain operator work.

## Update

```sh
sbfleet update myapp --to self-hosted/vX.Y.Z --dry-run
sbfleet update myapp --to self-hosted/vX.Y.Z --yes --identity /secure/backup.agekey
# After crash mid-promotion (unresolved UPDATING journal):
sbfleet update myapp --reconcile --operation-id <uuid> --yes
```

Replace X.Y.Z with an explicitly supported stable target from `REVIEWED_TRANSITIONS`. Plan/dry-run reports compatibility/manual gates without mutating the project. Apply creates a fresh recovery-verified backup inside the UPDATE transaction (requires `--identity` or `SBFLEET_AGE_IDENTITY`), runs official `update.sh` only in private staging, binds staged updater-owned vendor bytes to the approved `to_sha` snapshot, persists an operation-scoped promote-record, then mechanically promotes with durable per-path progress. Stale backup hints do not authorize apply.

**Interrupted update:** Ordinary status/doctor/update/restore/remove continue to refuse unresolved `UPDATING`. Do **not** “just retry update” or blindly “restore the pre-update backup” while the journal is unresolved — those gates reject the request. Use `--reconcile --operation-id` against the canonical promote-record (journal summary may lag). Pre-update archive remains valuable recovery evidence/data protection; **direct same-pin restore into a promoted different-pin destination is unsupported**; sbfleet does not claim generic cross-version rollback. Reconcile continues the same operation (no new backup, no replan, no new edge).

## Remove

`remove myapp --yes` requires explicit confirmation. Without `--no-backup`, remove refuses unless a loadable recovery-verified receipt exists. Backup archives outside the project directory are not deleted by remove. nginx configs/certificates are operator-owned and remain; generated instructions explain their cleanup. Remove invents proven-owned Docker IDs (no `--remove-orphans`); foreign/mismatched resources refuse. Never remove Docker resources by Supabase-like names alone.

## Recovery and troubleshooting

- Failed create: inspect `doctor` and operation journal; fix prerequisites/port conflict, `create SLUG --resume` preserves allocated identity/secrets. Do not delete unknown paths. For abandoned owned partial project use remove with explicit `--no-backup` if no recoverable DB backup exists.
- Failed update: apply refuses without a fresh recovery-verified backup inside the UPDATE lock; inspect vendor stamp/metadata, operation journal, and operation-scoped `promote-record.json`. Ordinary retry/restore are refused while `UPDATING` is unresolved. Use `update --reconcile --operation-id` when a promote-record exists; otherwise diagnose-only / manual operator recovery. Pre-update archive is evidence — not an automatic cross-pin rollback path. No blind downgrade/re-key/recreate loop.
- Failed restore: keep quarantine and journal when present, no automatic start of mixed state. Re-run restore after inspecting doctor/journal, or recover from the pre-restore recovery-verified backup. Never overwrite B to make A's data fit.
- Disk pressure: stop affected project's writers, inspect Docker stats/disk and per-project backup age. Free only explicitly selected old encrypted backups after off-host verification; no automated/global prune. Low disk during backup/update must fail before destructive action where preflight can predict it.
- Port collision: doctor identifies listener/resource; don't kill it or silently renumber projects. Resolve with operator or documented stopped metadata/.env/override reconciliation and full validation. No public DB binding workaround.
- Permissions: Docker helper can read/remove selected project container UID data; ordinary host files stay user-owned. Refuse unknown mounts/symlinks where implemented. Mutation authority invents ownership before destructive ops. No chmod 777 or root daemon workaround.
- Unhealthy Auth/Studio: check selected service logs, .env URL/key consistency, upstream health and SMTP capability; no secret dumps in bug reports. Auth signup delivery warnings are separate from process health.
- Missing Docker/CLI/age/nginx: prerequisite failure, not fabricated success. Sandbox cannot substitute for fleet project or vice versa.

Use sandbox start/status/studio/reset/destroy/env for disposable app work; see DEV_SANDBOX and implementation note. Proven adoption authority (SBF-contract/012) is implemented: fingerprint drift requires `--revalidate`; destroy/reset require adoption + owned inventory; not a hostile same-user boundary.
