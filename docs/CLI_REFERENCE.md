# sbfleet CLI reference

Practical operator manual for the implemented V1 CLI. Spec contract: [COMMAND_SPEC.md](COMMAND_SPEC.md). Architecture: [ARCHITECTURE.md](ARCHITECTURE.md).

Global options:

- `--home PATH` — absolute fleet data root (default: `$SBFLEET_HOME` or `~/.local/share/sbfleet`)
- `--version` / `-h`

Stable exit codes: `0` ok, `1` failure, `2` usage, `3` true absence (no `projects/<slug>/`), `4` prerequisite (tool/identity/age), `5` safety/confirm (including corrupt/incomplete managed state — directory present but `project.json` missing/malformed is **not** exit 3), `6` lock, `7` unhealthy, `8` backup integrity, `130` interrupt. `env` returns the child exit code.

---

## Starting sbfleet

```bash
sbfleet                 # interactive slash shell (TTY)
sbfleet --home /path    # same with explicit fleet root
sbfleet projects        # direct CLI (non-interactive)
```

In the shell, type `/` alone for slash discovery with live Tab completion.
Active project is session-only (not persisted). After interactive `/create`,
the new project becomes active automatically.

```text
sbfleet ❯
sbfleet ❯ /create myapp
Creating myapp
✓ Registry initialized
✓ Ports allocated
…
Start project now? [Y/n] y
Starting myapp...
✓ PostgreSQL
✓ Auth
…
Ready in 18.4s
sbfleet / myapp ● ❯ /status
sbfleet / myapp ● ❯ /studio
sbfleet / myapp ● ❯ /logs auth
sbfleet / myapp ● ❯ /backup
sbfleet / myapp ● ❯ /exit
```

The interactive shell may show an SBfleet identity banner and a cheap
fleet/docker/projects/sandbox summary on TTY startup (`NO_COLOR` honored).
The active-project prompt is `sbfleet / <slug> ● ❯`; the dot is green only
when session-cached health from a prior `/status` (or start/stop/restart/doctor)
reports `HEALTHY`. Direct CLI never prints the banner.

`/studio` checks real project health before opening a browser. If the project
is stopped:

```text
Project `myapp` is stopped.
Start it with `/start`.
Start it now? [Y/n]
```

Degraded stacks print a service breakdown and suggest `/status`, `/doctor`,
and `/logs` instead of opening Studio.

Suggestions filter as you type (`/st` → `/start`, `/status`, `/stop`, `/studio`)
and include short descriptions. Project and service names complete where applicable.

Direct CLI always requires an explicit project slug (except host-level `doctor`, `projects`, `sandbox`, `nginx install` help). There is **no** direct `sbfleet use` command. Direct output stays scriptable (no spinners); use `--json` where available.

---

## projects

| | |
|--|--|
| Purpose | List fleet projects |
| Syntax | `sbfleet projects [--json]` |
| Slash | `/projects` |
| Active project | No |
| Destructive | No |
| Confirmation | None |
| Output | Text table or JSON |
| Prerequisites | Fleet root |

```bash
sbfleet projects
sbfleet projects --json
```

---

## create

| | |
|--|--|
| Purpose | Create an official pinned Supabase project (STOPPED unless started) |
| Syntax | `sbfleet create SLUG [--name NAME] [--profile standard] [--domain DOMAIN] [--organization-name TEXT] [--studio-project TEXT] [--site-url URL] [--redirect-url URL ...] [--google-oauth] [--start\|--no-start] [--resume] [--yes]` |
| Slash | `/create …` |
| Active project | Interactive `/create` selects the new project as active |
| Destructive | No (allocates ports/dirs) |
| Confirmation | Interactive asks `Start project now? [Y/n]` (default Yes). Direct CLI starts only with `--start`. |
| Prerequisites | Docker, Node≥16, OpenSSL, Compose `!override` |

```bash
sbfleet create myapp --name "My App" --yes
sbfleet create myapp --start --yes
sbfleet create myapp --resume
sbfleet create myapp \
  --name "My App" \
  --domain auth.example.com \
  --organization-name Acme \
  --studio-project Orders \
  --site-url https://example.com \
  --redirect-url 'https://example.com/**' \
  --google-oauth \
  --yes
```

`--domain` sets the public Supabase/Auth hostname (`https://<domain>`). Studio display names (`--organization-name`, `--studio-project`) are independent of that hostname. See [SELF_HOSTED_OAUTH.md](SELF_HOSTED_OAUTH.md).

Interactive create shows live progress for registry/ports/upstream/secrets/compose
and optional start health. Direct CLI stays quiet and scriptable.

Errors: slug exists/incomplete (`5`), invalid slug (`2`).

---

## use (slash only)

| | |
|--|--|
| Purpose | Set session active project for subsequent slash commands |
| Syntax | `/use <project>` · `/use` (show) · `/use --clear` |
| Direct CLI | **Not implemented** — pass project explicitly |
| Destructive | No |

```text
sbfleet ❯ /use myapp
sbfleet / myapp ● ❯ /status
sbfleet / myapp ● ❯ /logs auth
```

With an active project, project-scoped slash commands omit the project argument.
An explicit project token still overrides the active selection when it names a
known fleet project. Without an active project or argument, the shell prints:

```text
No active project.
Use `/use <project>` or `/projects`.
```

`/commands` is an alias for `/help` (full palette). `/help status` shows topic help.
---

## start / stop / restart

| | start | stop | restart |
|--|--|--|--|
| Purpose | Start stack + health | Stop stack | Restart running stack |
| Syntax | `sbfleet start P [--timeout SECONDS]` | `sbfleet stop P` | `sbfleet restart P [--timeout SECONDS]` |
| Slash | `/start` `/stop` `/restart` (active or arg) | same | same |
| Destructive | No | No | Interrupts service |
| Confirmation | None | None | None |
| Exit | `7` if unhealthy after start | `1` on stop failure | `1` if not running / unhealthy |

Interactive `/start` and `/restart` show concise service/health progress.
On failure, a short redacted log tail and `/logs` `/doctor` `/status` hints are printed.

```bash
sbfleet start myapp --timeout 600
sbfleet stop myapp
sbfleet restart myapp
```

---

## status

| | |
|--|--|
| Purpose | Lifecycle + per-service health breakdown (not container existence alone) |
| Syntax | `sbfleet status P [--json]` |
| Slash | `/status` |
| Destructive | No |

```bash
sbfleet status myapp
sbfleet status myapp --json
```

Human output explains *why* (Postgres/Auth/REST/Gateway/Studio) and suggests
`/logs`, `/doctor`, or `/start` when useful. `--json` remains the script contract.

---

## configure

| | |
|--|--|
| Purpose | Show or change identity-neutral presentation settings (not slug rename) |
| Syntax | `sbfleet configure P [--name TEXT] [--organization-name TEXT] [--studio-project TEXT]` |
| Slash | `/configure` (active project or explicit P) |
| Destructive | No (file edits only; Studio Env apply needs later stop/start) |
| Confirmation | None |
| JSON | No |

```bash
sbfleet configure myapp
sbfleet configure myapp \
  --name "Orders App" \
  --organization-name "Acme" \
  --studio-project "Orders"
# apply Studio Env when the stack is running:
sbfleet stop myapp && sbfleet start myapp
```

Taxonomy:

- **SBfleet slug** — immutable in V1 (not changed by configure)
- **`--name`** — fleet `display_name` in `project.json` only
- **`--organization-name` / `--studio-project`** — Studio UI labels (`STUDIO_DEFAULT_*` + `branding.*`)

No flags → show CONFIGURED values and best-effort APPLIED studio-container Env (`yes` / `no` / `unknown` / pending next start). Plain `restart` does **not** refresh container environment. Missing project exit `3`; invalid labels `2`; unsafe `.env` / hard presentation drift `5`.

---

## studio

| | |
|--|--|
| Purpose | Open original Studio only after readiness succeeds |
| Syntax | `sbfleet studio P [--url-only] [--local]` |
| Slash | `/studio` |
| Destructive | No |

```bash
sbfleet studio myapp --url-only
sbfleet studio myapp
```

Stopped projects do **not** open a browser; the CLI explains how to `/start`
(and may offer start in the interactive shell). With `--url-only` on a stopped
project, the local/canonical URL is still printed, then exit 7. Browser open
uses Python `webbrowser.open` (no SSH/DISPLAY automation). Opener false/exception
prints a warning after the URL. Degraded stacks print failed checks and suggest
`/status`, `/doctor`, `/logs`.

---

## logs

| | |
|--|--|
| Purpose | Scoped Compose logs (redacted) |
| Syntax | `sbfleet logs P [SERVICE] [--tail N] [--follow]` |
| Slash | `/logs` · `/logs auth` · `/logs auth --follow` |
| Destructive | No |

```bash
sbfleet logs myapp db --tail 200
sbfleet logs myapp --follow
```

With an active project, `/logs` and `/logs auth` omit the project argument.
Service names autocomplete from the project compose file when available.

---

## doctor

| | |
|--|--|
| Purpose | Read-only host/project/sandbox checks |
| Syntax | `sbfleet doctor [P] [--sandbox PATH] [--json]` |
| Slash | `/doctor` |
| Destructive | No |

```bash
sbfleet doctor
sbfleet doctor myapp
sbfleet doctor --sandbox ~/app
```

Each check has an explicit criticality class. Exit priority: safety (5) >
prerequisite (4) > unhealthy (7). Informational UNKNOWN alone exits 0.
Authority-sensitive UNKNOWN/FAIL is nonzero. JSON `ok`, human rows and exit
derive from the same classification.
---

## connection

| | |
|--|--|
| Purpose | Non-secret connection endpoints (+ optional OAuth setup) |
| Syntax | `sbfleet connection P [--json] [--oauth-setup]` |
| Slash | `/connection` |
| Destructive | No |
| Note | Does not print JWT/DB passwords or Google secrets |

Human output labels **Host application (supported)** endpoints (`127.0.0.1` + allocated ports), states that **container applications are not supported in V1**, and that **remote PostgreSQL is not exposed by default**. JSON `--json` keeps the existing `data` field contract (no speculative container endpoints).

Container-internal Postgres listens on **5432**; the host port is `db_port` from this command — never assume host `5432`. Do not scrape `docker ps`.

```bash
sbfleet connection myapp
sbfleet connection myapp --oauth-setup
```

`--oauth-setup` prints Studio org/project labels, `API_EXTERNAL_URL`, `SITE_URL`, and the Google Authorized Redirect URI.

---

## env

| | |
|--|--|
| Purpose | Run a child with project credentials |
| Syntax | `sbfleet env (--admin \| --credentials-file FILE) [--service-role] P -- CMD…` |
| Slash | `/env` |
| Destructive | Child may mutate DB |
| Confirmation | Privileged; options required |
| Exit | Child status |

```bash
sbfleet env --admin myapp -- psql …
```

Flags must appear **before** the project slug.

---

## secrets

| | |
|--|--|
| Purpose | List secret **names**; `--reveal` prints values (dangerous) |
| Syntax | `sbfleet secrets P [--reveal] [--keys KEY1,KEY2]` |
| Slash | `/secrets` |
| Destructive | Reveal is sensitive |
| Confirmation | Prefer avoiding `--reveal` in shared terminals |

`--keys` limits listing/reveal to a comma-separated subset (Studio examples: `DASHBOARD_USERNAME,DASHBOARD_PASSWORD`).

```bash
sbfleet secrets myapp
sbfleet secrets myapp --keys DASHBOARD_USERNAME
# Do not --reveal on shared terminals
```

---

## backup

| | |
|--|--|
| Purpose | Cold encrypted age backup (PGDATA, Storage, db-config, env, …) |
| Syntax | `sbfleet backup P [--verify\|--no-verify] [--identity FILE]` |
| Slash | `/backup` |
| Destructive | Quiesces writers during backup |
| Prerequisites | `age`; `age_recipients` in `fleet.json`; identity for verify |

Configure **operator** recipients in `fleet.json` (`age_recipients`). Private identities live **outside** the fleet tree (mode `0600`). Acceptance tests use disposable keys under `~/.cache/sbfleet/acceptance-keys/` — do not commit them.

```bash
export SBFLEET_AGE_IDENTITY=~/.config/sbfleet/identity.agekey
sbfleet backup myapp
```

---

## restore

| | |
|--|--|
| Purpose | Decrypt + apply verified archive to the **same** project |
| Syntax | `sbfleet restore P ARCHIVE --yes [--identity FILE]` |
| Slash | `/restore` |
| Destructive | **Yes** — replaces data |
| Confirmation | `--yes` required |
| Prerequisites | Matching identity; stack stopped then restarted |

```bash
sbfleet restore myapp ~/backups/….tar.age --yes --identity ~/.config/sbfleet/identity.agekey
```

**Pre-mutation refusals** (wrong identity, missing/corrupt archive, wrong-project archive, manifest/prevalidation failure, requested disposable recovery-verification failure) refuse **before** a durable `RESTORING` journal is written. Target data stays unchanged; prior lifecycle remains truthful; subsequent `backup` / `update --dry-run` / `remove` are not blocked by that attempt. Operation-owned staging under `staging/restore-<operation_id>/` is cleaned best-effort; if cleanup fails, stderr reports residual **paths** (not file contents) while preserving the primary restore exit code — cleanup failure alone does not create a blocking `RESTORING` journal, and “quarantine retained” is printed only when quarantine was actually created.

**Post-boundary failures** (at/after `creating_pre_restore_backup` / quiesce / quarantine / install) leave a blocking `RESTORING`/`failed` journal. While that journal is unresolved, ordinary `backup` / `restore` / `update` / `remove` refuse (exit `5`). There is **no** public restore `--reconcile` (unlike `update --reconcile`). Do not invent `--force`.

---

## update

| | |
|--|--|
| Purpose | Plan/apply pinned official upstream transition, or continue one interrupted update |
| Syntax (apply) | `sbfleet update P --to self-hosted/vX.Y.Z [--dry-run] [--yes] [--identity FILE]` |
| Syntax (reconcile) | `sbfleet update P --reconcile --operation-id UUID --yes` |
| Slash | `/update` |
| Destructive | Maintenance; creates pre-update recovery backup when applying a non-noop transition |
| Confirmation | `--yes` required to apply or reconcile |
| JSON | `--dry-run` prints the plan JSON on stdout (there is **no** separate `--json` flag). Reconcile/diagnosis paths may also emit JSON on stdout/stderr. |
| Note | No automatic rollback or cross-pin restore; a pre-update archive cannot be restored into a promoted different-pin destination. Directed `REVIEWED_TRANSITIONS` only. |


Reconcile requires the canonical regular `staging/update-<operation_id>/promote-record.json`,
its original operation/backup/edge identity, and the complete original staged target.
Only that validated record is excluded from upstream byte comparison; arbitrary extra
files still refuse. Missing/replaced live paths refuse (a planned addition still absent
is an exact-source state). No-promotion and partial-promotion states resume only
exact-source paths. Complete promotion and runtime-verified/journal-incomplete states
also rebind staging and rerun runtime verification before advancing `last_verified_upstream`.
Missing or invalid evidence remains a nonzero refusal with retained staging and journal;
there is no new plan, backup, edge, operation identity, or generic rollback.

`--to` and `--reconcile` are mutually exclusive. `--reconcile` requires `--operation-id` and `--yes`; it does **not** support `--dry-run`. Without `--to` or `--reconcile`, update refuses (exit `5`).

Same-pin `--dry-run` builds the plan through cache materialization. If an old cache marker is missing `critical_digests`, that materialization can repair the marker as a side effect of planning; the dry-run may still exit `5` when same-target no-op validation fails (for example `last_verified-mismatch`). Cache rematerialization can restore startability after missing digests; doctor `vendor-integrity` remains the integrity signal. `last_verified_upstream` advances **only** after a successful reviewed update apply or `--reconcile` that completes runtime verification — not by `start`, `doctor`, status, create, or `--dry-run`. For never-updated same-pin projects, dry-run exit `5` on noop does **not** by itself mean digests were unrepaired. Do not invent a separate “HEALTHY verify” action that writes `last_verified`.

```bash
sbfleet update myapp --to self-hosted/v0.8.2 --dry-run
sbfleet update myapp --to self-hosted/v0.8.2 --yes --identity ~/.config/sbfleet/identity.agekey
# Interrupted UPDATING only (exact operation_id from journal/promote-record):
sbfleet update myapp --reconcile --operation-id <uuid> --yes
```

---

## remove

| | |
|--|--|
| Purpose | Ownership-safe project deletion (backups retained) |
| Syntax | `sbfleet remove P --yes [--no-backup]` |
| Slash | `/remove` |
| Destructive | **Yes** |
| Confirmation | `--yes`; refuses without backup hint unless `--no-backup` |

```bash
sbfleet remove myapp --yes
```

Never runs global Docker prune.

---

## sandbox

Local official Supabase CLI **v2.118.0** only. No Cloud login/link.

Parent flags (before action): `--yes`, `--json`, `--revalidate`, `--migration-mode supabase|external`.

| Action | Syntax | Confirm | Notes |
|--|--|--|--|
| start | `sbfleet sandbox [--migration-mode MODE] [--revalidate] start PATH` | — | Requires `supabase/config.toml` with `sbfleet-dev-` / `sbfleet-test-` / `sbfleet-sb-` `project_id`. `--revalidate` updates fingerprint only (project ID immutable). |
| status | `sbfleet sandbox [--json] status PATH` | — | Keys redacted with `--json` |
| studio | `sbfleet sandbox studio PATH` | — | Prints loopback Studio URL (no `--url-only` flag; URL print is the default) |
| stop | `sbfleet sandbox stop PATH` | — | Data kept |
| reset | `sbfleet sandbox --yes reset PATH` | `--yes` | Local DB reset |
| destroy | `sbfleet sandbox --yes destroy PATH` | `--yes` | Volumes discarded |
| env | `sbfleet sandbox env PATH -- CMD` | — | Injects local `DATABASE_URL` / keys |

Prefer flags before the action: `sbfleet sandbox --yes destroy PATH`.

Drizzle-style: disable supabase migrations in config, then `sandbox env -- bun run db:migrate` (or SQL stand-in).

---

## nginx

| Action | Purpose | Host `/etc/nginx` |
|--|--|--|
| `generate P` | Write `projects/P/generated/nginx.conf` | Untouched |
| `validate P` | Private `nginx -t -p` | Untouched |
| `install` | Print **INSTRUCTIONS_ONLY** | Untouched |

Domain required for validate. Templates without domain are not installable.

```bash
sbfleet nginx generate myapp
sbfleet nginx generate myapp --json
sbfleet nginx validate myapp
sbfleet nginx install
sbfleet nginx install myapp
```

`--json` is supported on `nginx generate` (and accepted by the nginx parent parser). Install remains **INSTRUCTIONS_ONLY** — never mutates host nginx.

---

## help / exit

- `sbfleet --help` / `-h` on any subcommand
- Shell: `/help [cmd]`, `/` discovery, `/exit` (EOF/Ctrl-D)
- Direct `sbfleet exit` / `sbfleet help` are **not** commands (usage `2`)

---

## Age recipients (operators)

1. Generate identity privately: `age-keygen -o identity.agekey` (mode `0600`)
2. Put the **recipient** (`age1…`) in `fleet.json` → `age_recipients`
3. Keep the identity file outside the fleet/git tree
4. Set `SBFLEET_AGE_IDENTITY` for backup verify / restore

Acceptance fixtures must use disposable sbfleet-owned keys, never personal production keys.

## Fleet observation interfaces

- `sbfleet [--home /absolute/fleet] status --all [--json]`
- `sbfleet [--home /absolute/fleet] dashboard [--once] [--refresh SECONDS]`
- `sbfleet [--home /absolute/fleet] mcp`

`status PROJECT [--json]` retains its existing format and behavior. `PROJECT` and
`--all` are mutually exclusive. Fleet JSON is a separate, versioned contract:
`schema_version = "sbfleet.fleet.v1"`. Its JSON Schema ships as
`sbfleet/fleet.schema.json` in the wheel. Keys and project ordering are deterministic;
`observed_at` and backup ages naturally change on each observation. Output is
non-interactive. Exit 0 means observation completed, not that every project is
healthy; exit 7 means at least one observation failed. Consult states and attention
fields for readiness. An absent root is UNKNOWN and is never initialized.

The snapshot contains totals, managed projects, state, runtime/health summaries,
allocated ports, loopback endpoints, Studio URL, recorded upstream ref/commit,
service checks, unresolved-operation flag and backup evidence. Totals include
HEALTHY, STOPPED, FAILED, UNKNOWN and `other` (STARTING/DEGRADED/UNHEALTHY) so
counts sum to the project total. `needing_attention` includes missing/unverified
backups. No passwords, keys, raw diagnostics, archive paths or backup identities
are returned. Display names use configured secret redaction. Endpoints are host
loopback addresses; they do not imply reachability from another machine.

Backup coverage counts only the latest registered backup when the existing
recovery-evidence authority validates its archive binding and verification time.
This hashes the archive and may be slow for large backups. Missing evidence is
UNKNOWN, not successful verification. `NONE` means no latest backup is registered.
The snapshot does not search historical archives. Observation is sequential and
not an atomic transaction across projects. Status probes retain existing timeouts.
`update_available: null` means no truthful update comparison was established;
no upstream network fetch is performed. Observation uses the existing fixed
Docker, HTTP and SQL health probes; it accepts no agent-supplied commands. Resource usage is UNKNOWN; service checks
are not CPU/memory metrics. The project list covers fleet-managed deployments;
sandbox adoption is separate, hence `sandbox: "NOT_APPLICABLE"` for these rows.

### Read-only terminal dashboard

In the interactive shell, `/dashboard` invokes the same dashboard, with the same
options. It appears in `/help` and command completion. Quitting returns to the shell.

The dashboard uses the already-installed `prompt_toolkit`. Arrow keys select a
project; `r`/`R` refreshes, Enter opens details, and `?` opens help.
`q`/`Q` or Ctrl-C exits; Esc closes a view or exits from the overview.
PgUp/PgDn scroll lower panels. Wide terminals pair panels; narrow terminals stack
panels, and very small terminals retain core status and exit controls.
`--refresh` defaults to 0 (manual)
and accepts 5–3600 seconds when enabled. Refreshes never overlap. Collection runs
off the UI thread; existing probes may finish after quit. Redirected input/output
and `--once` print one snapshot without a fullscreen terminal. There are no
start, stop, remove, restore or update actions.

### Local-only read-only MCP

The packaged official MCP Python SDK serves stdio only. Start one process per
agent connection, using the same user permissions as the fleet owner. Example
MCP client configuration (replace the absolute paths):

```json
{
  "mcpServers": {
    "sbfleet": {
      "command": "/home/you/.local/bin/sbfleet",
      "args": ["--home", "/home/you/.local/share/sbfleet", "mcp"]
    }
  }
}
```

Original fleet tools: `fleet_summary`, `list_projects`, `project_status(slug)`,
`project_connection_info(slug)`, `backup_status(slug)`, `doctor_summary(slug)`.
All have explicit input/output schemas and read-only annotations. Each fleet-tool request
collects the canonical snapshot; there is no persistent cache. The first two
return the full snapshot so callers retain completeness and fleet errors.
`doctor_summary` summarizes canonical runtime checks and attention only; it does
not claim to run the full host/sandbox doctor. Unknown tools fail. Missing slugs
return NOT_FOUND only after a complete observation, otherwise UNKNOWN. There is
no reveal option, command execution argument, remote listener or mutation tool.

## Verified same-pin clone

```text
sbfleet [--home PATH] clone SOURCE TARGET [--identity PATH] [--json]
```

TARGET must not exist. An age identity must be supplied via `--identity` or
`SBFLEET_AGE_IDENTITY`, and fleet backup recipients must already be configured.
The source must be an authority-proven, initialized standard/file-storage project
at the exact supported `self-hosted/v0.8.2` / `564eab8ad7840b13324f68b1bfac074ef8d51c21`
pin, with the reviewed default pooler schema and single tenant/manager state.
Custom pooler mappings, schema drift and cross-pin copies are refused.

Clone takes a fresh recovery-verified backup, creates a new project identity and
placement, installs the supported payload, rebinds the pooler tenant, verifies
recovery facts and both pooler connection modes, and leaves TARGET **STOPPED**.
Verification temporarily starts the destination. SOURCE returns to its prior
runtime state through the existing bounded backup/quiesce contract.

JSON uses `schema_version: "sbfleet.clone.v1"` and includes source, target, pin,
destination identity/ports, operation_id, verification, final_state, success and
safe attention classifications. Exit 0 means verified success; exit 5 means
refusal/failure. Operation evidence is retained under `HOME/clone-operations`.
If ownership cannot be proven during failure cleanup, the target is retained for
review; there is no broad cleanup fallback. Plaintext cleanup failure is nonzero.

Application JWT/API and physical-recovery credentials/crypto remain source-bound;
this is not credential rotation. Dashboard credentials are destination-owned.
See [secret and identity contract](BACKUP_RESTORE.md#verified-same-pin-clone).
The existing fleet JSON, dashboard and read-only MCP tools observe the new target.
There is no MCP clone mutation tool. Ordinary restore remains same-project only.

## Schema diff and migration plan

```bash
sbfleet schema diff SOURCE TARGET
sbfleet schema diff SOURCE TARGET --json
sbfleet migrate plan SOURCE TARGET
sbfleet migrate plan SOURCE TARGET --json
```

SOURCE is desired and TARGET is current: ADDED means present in SOURCE but absent
from TARGET, REMOVED means present only in TARGET. CHANGED compares facts under the
same stable identity; UNSUPPORTED signals an operation outside the modeled semantics.
Changes are not executable steps or dependency-ordered SQL. There is no `migrate apply`
and no SQL preview. Exit 0 includes schemas with differences or unsupported inventory;
exit 5 means observation or safety failure, reported as UNKNOWN rather than an empty diff.
Neither command initializes a fleet or starts a stopped project.

Both use `sbfleet-schema-v1`. JSON contracts `sbfleet.schema-diff.v1` and
`sbfleet.migration-plan.v1` ship with JSON Schemas in the wheel, alongside the snapshot
schema. Stable sorted identities are arrays (namespace, object, optional member/signature),
not ambiguous dot-joined strings. No timestamps or catalog OIDs enter comparison.
Before is TARGET and after is SOURCE. Diff JSON includes pins, summary counts,
differences, unsupported inventory, limitations and a safe error code. Plan JSON wraps
that exact diff and adds classifications/reasons. Identical schemas have an empty material
diff even when unsupported inventory is present.

Snapshots cover the `postgres` application database only; the separate `_supabase`
pooler database is outside this comparison contract.

Supported catalog facts: schemas; ordinary tables; column order, type identity, nullability,
default/generation/identity/collation facts; PK/unique/FK/check/exclusion constraints;
index uniqueness, definition, predicates and validity; function/procedure signatures,
return types, language and definitions; enabled/forced RLS; policy command, roles,
permissiveness, USING and WITH CHECK; views/materialized views; enums; sequence parameters
and ownership (not current values); non-internal triggers; extension version inventory.
SQL expressions, defaults, enum labels and function/view/trigger definitions are represented
by SHA-256 fingerprints, so embedded literal secrets are not emitted. Equality is stable
catalog deparse text, not a proof of semantic equivalence. Configured secrets in identifiers
cause safe observation refusal. No function body or policy expression is executed.

Namespace classifications:

- SYSTEM: `pg_*` and `information_schema`; omitted from object comparison.
- SUPABASE_MANAGED: `auth`, `storage`, `_realtime`, `realtime`, `supabase_functions`,
  `pgbouncer`, `vault`, `net`, `graphql`, `graphql_public`, `extensions`, `_supavisor`.
  Non-extension-owned objects remain visible, including Auth and Storage. Their plans
  require at least review rather than promising safe platform changes; destructive
  removals/type changes retain DESTRUCTIVE classification.
- APPLICATION: all other namespaces, including `public` and user schemas.
- IGNORED: extension-owned internals. Extension name/version/namespace remain in the
  unsupported inventory; SBfleet does not plan extension migrations.

PARTIAL/UNSUPPORTED: partition/inheritance semantics, foreign/composite relations, custom
base/domain/range types, aggregates, rewrite rules and extension operations. Owner/ACL/grant,
comment/security-label, publication/subscription, event-trigger, collation-definition,
foreign-server, operator-class and role/database-setting changes are outside this model.
These limitations are returned on every diff, not silently treated as equality.

Planning is conservative: ordinary application schema/table additions and nullable columns
of reviewed built-in scalar types without defaults, identity or generation are SAFE
as individual operations. Domain, enum, array and other custom-type additions require review. Other dependent
items still need review. Initial disabled RLS records are SAFE. All index additions require
review for locking and expression semantics. FK/unique/check constraints, functions,
policies, RLS changes, defaults and non-null additions are REVIEW_REQUIRED. Table/column/
schema/sequence/enum/materialized-view removals are DESTRUCTIVE. All column type
changes are conservatively DESTRUCTIVE: no widening/cast safety is inferred. Unsupported
object operations are UNSUPPORTED. SAFE does not mean the whole plan is safe to execute.

Only the reviewed `self-hosted/v0.8.2` commit
`564eab8ad7840b13324f68b1bfac074ef8d51c21`, PostgreSQL major 17, is supported in this run.
Cross-pin diff and planning refuse. Schema planning is not a Supabase version upgrade;
use the reviewed updater for that. Each database is read in its own repeatable-read,
read-only transaction with a 15-second statement timeout, 2-second lock timeout and
25-second client deadline. Two databases are not observed atomically. Concurrent DDL may
require another manual observation; results are not cached or refreshed by the dashboard.

### Schema MCP tools

The existing local-only stdio MCP server additionally exposes `schema_diff(source, target)`
and `migration_plan(source, target)`. They call the same production services as CLI and
accept exact project slugs only, never SQL, shell commands or lifecycle actions. The six
original observation tools retain their contracts. The two new tools return the same
versioned diff/plan JSON, including UNKNOWN and unsupported inventory. No clone, mutation,
SQL execution endpoint or `migrate_apply` tool is exposed.
