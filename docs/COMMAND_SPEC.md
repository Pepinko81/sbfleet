# V1 command contract

Honesty note: the main body below is the **active V1 executable syntax** only (what the current parser/handlers accept). Deferred or historical ideas live only in **Future / Not Shipped / Non-contractual** at the end — they must not be read as shipped grammar. Hardening Runs 2A–2D shipped ownership, recovery backup/restore, staged update, and sandbox adoption.

## Shared grammar and output

`SBFLEET_HOME`/`--home PATH` choose root; --home is a global option before command. `sbfleet` with TTY enters shell; no arguments without TTY prints help, exit 2. No direct command relies on active project. Optional `[P]` omission is allowed only in shell when /use has selected a project; direct mode requires P. All slugs are validated before subprocess work. Shell resolution: if the first positional token is an existing project slug, it is the explicit P; otherwise an active project supplies P and the token belongs to the remaining arguments. If a service name also names a project, explicit project selection wins; `/logs ACTIVE auth` removes ambiguity. With no active project, a project token is mandatory. sandbox paths and restore archive positional arguments use their command-specific grammar, never a guessed Cloud/project target.

Stable exit codes: 0 success (including verified idempotent no-op), 1 operation/subprocess failure, 2 usage/invalid input, 3 **true absence** (no `projects/<slug>/` tree / unknown managed project), 4 missing/incompatible prerequisite (tool/identity/age), 5 safety/ownership/confirmation refusal (including corrupt/incomplete managed state such as directory present but `project.json` missing/malformed), 6 lock timeout, 7 unhealthy/degraded observation or health timeout, 8 backup integrity/version compatibility failure, 130 interrupted. Exit 3 must **not** be used for corrupt/incomplete project trees. `env` is the exception: returns child's exit status, signals as 128+signal; wrapper errors use the above codes before spawn. No internal tracebacks by default.

JSON supported only on projects/status/doctor/connection, sandbox status, update --dry-run and nginx generate. Schema: `format_version:1`, `ok`, `command`, `data`, `warnings` array, `errors:[{code,message}]`. JSON goes to stdout, diagnostics stderr, no ANSI. Health/doctor missing facts are `unknown`, not healthy. JSON keys are stable within v1; order is not contractual. No secrets in any supported JSON. Human outputs compact; output names explicit about config-created vs running/healthy, and backup receipt verification level (`none` / `decrypt_structural` / `recovery`) rather than implying recoverability from decrypt-only receipts. There is **no** `update --json` flag — dry-run JSON is emitted by `--dry-run` alone.

Confirmation: noninteractive commands never read prompts. Destructive restore/remove require `--yes`. Sandbox reset/destroy require `--yes`. Update apply requires `--yes` but still refuses without a recovery-verified backup receipt. Create `--yes` accepts wizard defaults, not unsafe overwrite. No raw upstream extra flags.

## Direct and slash commands

Each `/name` below uses the same parser/handler and exit/error semantics as `sbfleet name`. Shell catches usage failures and returns to prompt; direct mode exits. Global options in shell are not dynamically changed.

### projects

`projects [--json]` / `/projects`. Input registry; output slug/display/status/profile/ref/Studio/backup age. Read-only, repeatable. Malformed rows displayed FAILED with per-row error and exit 1, never silently omitted; valid others still shown. Empty registry succeeds. No confirmation.

### create

`create SLUG [--name TEXT] [--profile standard] [--domain HOST] [--organization-name TEXT] [--studio-project TEXT] [--site-url URL] [--redirect-url URL ...] [--google-oauth] [--start|--no-start] [--yes] [--resume]` / `/create [SLUG ...]`. Wizard asks slug/display, shows sole standard profile, optional domain and start (default no). Direct defaults to no-start; SLUG required. Outputs assigned URLs/ref/state, no credentials. Creates unique secrets/config/reservations transactionally. Existing complete slug refuses (5); --resume only incomplete same-owned project, preserves secrets/data/ports. Never overwrites unknown directory. Tool absence 4, health failure 7 and FAILED registry. No JSON. Optional domain is stored in metadata only — run `nginx generate P` explicitly for a template; create does not write nginx config. Studio display names (`--organization-name`, `--studio-project`) are independent of slug/`--name`; post-create changes use `configure`.

### use

Interactive `/use P` validates registry then changes prompt to `P >`; `/use` reports active project; `/use --clear` clears. No persistent state or direct `use` command (direct attempt 2 with explanation). Selection doesn't start services or grant destructive permissions. Missing 3, no mutation/confirmation, repeatable.

### start / stop / restart

`start P [--timeout SECONDS]`, `stop P`, `restart P [--timeout SECONDS]` / matching slashes. start/stop guarded idempotent; restart deliberately interrupts service, requires running stack, repeated call repeats restart. Output actual final state. No data deletion or prompt; project lock required. Mutations pass the shared authority gate (recompute identity, force Compose selectors from metadata, effective Compose contract, live ownership where resources exist). Ordinary start refuses unresolved maintenance/destructive journals. start/restart verify all health; stop verifies no running containers. Invalid port/pin/ownership 5, health 7. No JSON (use status).

### status

`status P [--json]` / `/status [P]`. Read-only actual state with service statuses, profile, vendor and last verified refs, gateway/Studio, DB direct/pooler addresses without credentials, latest backup receipt age (with verification level when known; decrypt_structural is not recovery), disk usage only if cheap/cached with timestamp/unknown flag. Exit map: HEALTHY/STOPPED/STARTING → 0 (status successfully observed a valid known lifecycle — **not** ready unless lifecycle is HEALTHY); DEGRADED/UNHEALTHY/UNKNOWN → 7; FAILED (including unresolved RESTORING/UPDATING/REMOVING/BACKUP journals — failed, interrupted, **or durable in-progress after process death**) → 1. Ordinary status never ignores in-progress maintenance; nested lock-owning mutation verification uses an internal MutationContext-scoped API only. JSON `ok` is true only for HEALTHY. Human text, JSON lifecycle/`ok`, and exit must agree. Don't block behind a long mutation; show operation journal and unknown probes as appropriate. Repeatable, no confirmation.

### studio

`studio P [--local] [--url-only]` / `/studio [P]`. Prints official Studio URL and optionally opens OS browser under STUDIO_AND_NGINX policy. Read-only, no secret URL/confirmation. Unknown project 3. Opener error warning, printed URL success; unavailable stack is explicitly labelled unavailable, exit 7. No health claim from URL construction.

### logs

`logs P [SERVICE] [--follow] [--tail N]` / `/logs [P] [SERVICE] ...`. Default last 100 lines and exit (automation-safe); --follow streams. Validate service against resolved standard inventory; no arbitrary flags. Scoped Docker logs via Compose; run.sh logs can be used for --follow only. Read-only, possibly secret-bearing application text; exact fleet credential redaction. Exit child errors 1, Ctrl-C 130. No JSON/confirmation or persistent log store.

### doctor

`doctor [P] [--sandbox PATH] [--json]` / `/doctor [P]`. No project means host checks. --sandbox mutually exclusive with P. Read-only checks reuse shared validators (production effective Compose contract, live ownership with recorded image IDs when available, secret-file mode, unresolved journal, recovery-archive usability, vendor integrity, health). Compose-contract FAIL when the approved vendor/image contract cannot be loaded — never PASS a reduced contract. Runtime image checks distinguish **CURRENT** (live inspect of owned containers' image ref/ID) from **RECORDED** (`image_digests` metadata); container enumeration count alone is not labeled as image inspection. Each check has an explicit criticality class (`safety` / `prerequisite` / `health` / `informational`). Exit priority: safety (5) > prerequisite (4) > unhealthy (7); informational WARN/UNKNOWN alone → 0. Authority-sensitive UNKNOWN/FAIL (identity, Compose, ownership, secret-file, journal, required recovery archive, critical prerequisites) is nonzero. Human rows, JSON `ok`, check state and exit derive from that classification. No mutation/install/fix mode. Ordinary diagnostic reasons pass through the configured credential redaction boundary before truncation.

### configure

`configure P [--name TEXT] [--organization-name TEXT] [--studio-project TEXT]` / `/configure [P] …`. Show or change identity-neutral presentation settings. **No flags:** read-only display of CONFIGURED fleet `display_name` + Studio organization/project (from durable files) and best-effort APPLIED studio-container Env (`yes` / `no` / `unknown` / pending next start). With flags: validate conservatively; under registry+project lock, refuse unresolved maintenance journals; mutate only requested fields. `--name` updates `project.json.display_name` only (does **not** rename slug). Studio flags dual-write `project.json.branding.*` then allowlisted `STUDIO_DEFAULT_ORGANIZATION` / `STUDIO_DEFAULT_PROJECT` in `deployment/.env` (mode-preserving atomic rewrite); on second-write failure roll back meta; rollback failure reports presentation drift — never false success. Secrets, ports, slug, UUID, Compose/Docker identity unchanged. Plain `restart` does not apply Studio Env; operator must `stop` then `start`. No JSON / `--apply` / confirmation. Missing project 3; invalid labels 2; unsafe `.env` / lock / drift-hard-fail 5.

### connection

`connection P [--json]` / `/connection [P]`. Returns API/Studio URLs, 127.0.0.1 endpoints/ports, DB name, direct postgres admin role label and pooler username pattern `<role>.<tenant>`. Explains runtime-role setup; no secrets or password-bearing URL. Read-only, repeatable, no confirmation.

### env

`env P (--admin | --credentials-file FILE) -- COMMAND [ARG...]` / `/env [P] ...`. Explicit authority choice required (otherwise 2). Admin injects DATABASE_URL/PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD for direct loopback DB using postgres role and secret password; also SUPABASE_URL and publishable/anon key, never service-role key unless separate `--service-role` flag is explicitly requested. Runtime file is mode-0600 JSON `{role,password}` for an app-created least-privilege role, not a URL/host override; no credential file is persisted by sbfleet. Validate no reserved admin role in runtime mode. Percent-encode URL credentials. Scrub inherited DB/Supabase target variables, inject only selected target, hold project lock through child. No shell, no command echo with secrets, no confirmation beyond explicit authority flags. Returns child's exit. Arbitrary child effects are user's authorized responsibility; never call this against production in sandbox workflow.

### secrets

`secrets P [--reveal] [--keys K1,K2]` / `/secrets [P] ...`. Default names and redacted values. Explicit reveal emits warning stderr then sensitive .env values stdout. `--keys` limits list/reveal to named keys (Studio workflow: `DASHBOARD_USERNAME,DASHBOARD_PASSWORD`). Read-only/no JSON/history retention; flag is the deliberate action, no second prompt. Refuse output from malformed/unsafe .env (5).

### backup

`backup PROJECT [--verify|--no-verify] [--identity FILE]` / `/backup [P] ...`.

**Implemented now (prior hardening work. Recipients remain fleet.json `age_recipients` (no CLI `--recipient`). Receipt levels: `none`, `decrypt_structural`, or `verification=recovery` only after disposable `RecoveryVerificationResult` succeeds (not project HEALTHY). Prior HEALTHY stacks are restarted after backup; STOPPED left stopped. Backup OK + restart fail → nonzero with recovery backup preserved. Operator output states `recovery_verified=True|False` honestly.

Direct command authorizes documented downtime. Not idempotent: every success gets a new backup id. No plaintext switch/JSON.

### restore

`restore PROJECT ARCHIVE [--yes] [--identity FILE]` / `/restore [P] ARCHIVE ...`.

**Implemented now (prior hardening work. **Pre-mutation preflight** (decrypt, manifest/identity prevalidation, disk preflight, disposable requested-archive recovery verification) runs **without** writing a durable `RESTORING` journal. Primary preflight refusal returns the existing exit code, leaves prior journal unchanged, attempts honest cleanup of operation-owned staging (reports residual paths on stderr if cleanup fails; does not invent RESTORING solely for cleanup failure), and does not claim quarantine retention when quarantine was never created. **Durable `RESTORING` begins** only after successful recovery verification, immediately before `creating_pre_restore_backup` (runtime quiesce / first target mutation). Post-boundary failures call `fail_operation` (blocking `RESTORING`/`failed`); quarantine is retained only when it was created. Field-level `.env` reconciliation + Run 2A revalidation; RESTORED only after destination HEALTHY. No public restore `--reconcile` / `--force`. No JSON.

### update

`update PROJECT --to REF [--dry-run] [--yes] [--identity PATH]` /
`update PROJECT --reconcile --operation-id UUID --yes` /
`/update [P] ...`.

**Implemented now (prior hardening work. Directed `REVIEWED_TRANSITIONS` only. `--dry-run` does not mutate the live project journal/stack; it may rematerialize the pin cache via `materialize_cache` (for example repairing missing `critical_digests`) while still exiting 5 when same-pin no-op validation fails (`last_verified-mismatch`). `last_verified_upstream` advances **only** after a successful reviewed update apply or `--reconcile` that completes runtime verification — not by `start`, `doctor`, or `--dry-run`. Apply under one UPDATE lock: fresh recovery-verified pre-update backup (`--identity` / `SBFLEET_AGE_IDENTITY`), official source-pin `update.sh` in private 0700 staging (finite timeout), fail-closed conflict/`.dist` handling, destination-owned `.env` reconciliation + override regen, **operation-scoped canonical `promote-record.json`** (exact pre/target path states + per-path progress; journal pointer/summary may lag), mechanical promotion with verify-before-progress, runtime verification; prior STOPPED restored after success.

**Interrupted update (`--reconcile`):** Continues the **same** unresolved `UPDATING` `operation_id` from its canonical promote-record. Requires maintenance lock + exact operation identity. Diagnoses live type/state/hash vs frozen plan; refuses foreign/unexpected paths. Does **not** create a new recovery backup, rebuild the plan, select a new edge, or replace the operation identity. If staging can be cryptographically rebound to the original approved target, resumes only remaining exact-source promotions then downstream pull/start/verify/metadata/journal completion. If staging is missing or cannot be rebound → diagnose-only. Same-pin restore of the pre-update archive into a promoted different-pin destination remains unsupported; sbfleet does not claim cross-version rollback.

**Evidence:** unit/process `tests/unit/test_update_promote_reconcile.py`, `tests/process/test_update_promote_process_death.py`, `tests/unit/test_update_fault_injection.py`, `tests/process/test_update.py`; disposable Docker `tests/acceptance/test_update.py`.

JSON only for `--dry-run` (reconcile prints JSON diagnosis/result on stdout).

### remove

`remove PROJECT --yes [--no-backup]` / `/remove [P] ...`.

**Implemented now (prior hardening work. Foreign/mismatched resources refuse with residual report. No JSON.

### nginx

`nginx generate P [--json]`; `nginx validate P`; `nginx install P` / matching `/nginx ...`.

**Implemented now:** deterministic generate into `projects/<slug>/generated/nginx.conf` (refuse overwrite when content differs); template without domain labelled not ready; with domain still `ready_to_install: false` until operator supplies host certs (OPTIONAL — not install-ready HTTPS). Validate runs private `nginx -t` on **SSL-listen-stripped** syntax-check text; never reloads host; success is not proof of the TLS deliverable. Install prints manual steps only (INSTRUCTIONS_ONLY); exit 0 means instructions generated, never INSTALLED. Active grammar has no `--output` / `--certificate` / `--force` / install `--yes`.

### sandbox

`sandbox {start,status,stop,reset,studio,destroy,env} PATH` / `/sandbox ...` (PATH required). status supports `--json`; reset/destroy require `--yes`; start supports `--migration-mode supabase|external` and `--revalidate` (fingerprint re-adoption only); env requires `-- COMMAND ...` with child argv preserved (parent does not consume child `--yes`/`--json`). Honors fleet `--home` for sandbox state root.

**Implemented (Run 2D + prior release + prior release):** pinned CLI 2.118.0; real TOML parse; locked adoption (canonical root + UUID + unique project ID + fingerprint + inventory); crash-consistent project-id index; **immutable project ID after adoption** (`--revalidate` updates fingerprint only); **post-lock authority reread**; **per-class live ownership** before **start**/stop/reset/destroy/env (adopted start observes live namespace before CLI dispatch; post-start failure cleanup is attempt-delta only — `post_owned − pre_owned` — never broad `stop --project-id`; no cached-volume destroy fallback; full-namespace residual reinspect); fail-closed linked/dotenv grammar/network/binding/endpoint locality (PG query allowlist empty for CLI local URLs; HTTP no userinfo); `--migration-mode`; `env` no-spawn on UNKNOWN/absent; doctor `--sandbox` authoritative read-only checks. No passthrough remote flags. Hostile same-user isolation is **not** claimed.

### help / exit / slash discovery

`--help` and shell `/help [COMMAND]` print usage, available commands and safety flag descriptions; exit 0. There is **no** direct `help` subcommand — `sbfleet help` is usage error 2 (see CLI_REFERENCE). `/` alone prints all slash commands with one-line descriptions and active project, without executing anything. `/exit`, EOF and Ctrl-D exit shell cleanly; Ctrl-C cancels current input/child, preserves journal and returns prompt unless a second interrupt requests exit. Direct `exit` is unsupported usage 2. Unknown slash or bare shell input prints help error; no fallback shell execution. Parse with shlex, no eval. readline completion is optional; persistent history disabled to avoid storing reveal commands/paths/credentials. Interactive startup (TTY stdout only) may print an SBfleet ASCII identity banner and a cheap read-only fleet/docker/projects/sandbox summary; honor `NO_COLOR`; never emit ANSI into JSON or piped/non-TTY output. Prompt is `sbfleet ❯` or `sbfleet / <slug> ● ❯`. The project dot is green only when a session-cached lifecycle from a prior authoritative status-path command (`/status`, `/start`, `/stop`, `/restart`, project `/doctor`) reports `HEALTHY`; otherwise neutral. The prompt never polls Docker/health merely to decorate. Non-TTY piping uses direct CLI, not an interactive automation protocol.

## Future / Not Shipped / Non-contractual

The following are **not** active V1 grammar. They may appear in roadmap or historical notes only:

- `backup all`; CLI `--recipient` (recipients stay in `fleet.json`)
- `restore --recover` for absent projects; restore clone; public restore `--reconcile` / `--force`
- `update --json` as a separate flag (use `--dry-run` for plan JSON)
- remove `--identity`; resumable multi-phase remove journal for every failure branch
- sandbox typed `project_id` confirmation beyond `--yes`
- nginx `--output`, `--certificate`, `--certificate-key`, `--force`, install `--yes`/`--file`, host `/etc/nginx` mutation, DNS/TLS automation, validated deliverable TLS with cert paths
