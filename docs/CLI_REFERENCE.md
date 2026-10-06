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
| Note | No automatic irreversible-migration rollback — restore the pre-update backup. Directed `REVIEWED_TRANSITIONS` only. |

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
