# Disposable app-local development

> **STATUS:** Proven adoption authority for SBF-contract/012 plus V2-007/008/015/016/020 and V3-005 repairs: live per-class ownership before **start**/stop/reset/destroy/env, attempt-delta post-start cleanup, post-lock authority reread, immutable adopted CLI project ID, complete locality/config/inspect guards, exception-safe dual locks. See implementation note. This is a safer command boundary for normal workflows — **not** a hostile same-user security sandbox.

## Separate authority

A sandbox uses official Supabase CLI v2.118.0 initially, its app-owned `supabase/config.toml`, migrations/seed/functions where applicable, and CLI-owned local Docker resources. It is never an sbfleet long-lived deployment and never imports fleet .env. No Supabase account, login, link or access token is required. Prefer the **managed** CLI installed by `scripts/install-user.sh` (absolute-path under the active `~/.local/lib/sbfleet/current/` generation; not a public PATH shim). PATH/`npx`/other-project `node_modules` binaries are not an acceptable supply path; sbfleet does not fetch executable npx packages implicitly. Unmanaged/dev PATH fallback requires `SBFLEET_ALLOW_PATH_TOOLS=1` (or no managed prefix) and still refuses `/node_modules/` and wrong versions.

Supported adapter: legacy local backend of v2.118.0, `SUPABASE_EXPERIMENTAL_STACK=0`; reject experimental stack/declarative modes and config.json ambiguity. Version mismatch requires explicit tested adapter support. `sandbox doctor` is not a separate command: `doctor --sandbox PATH` reports guards and compatibility (PASS/FAIL/UNKNOWN; read-only; no auto-fix/adopt). No arbitrary CLI passthrough.

## Adoption and identity

First `sandbox start PATH` requires app `supabase/config.toml` already initialized. Do not overwrite it or run init --force. If no config, print the explicit operator command `supabase init` in that repository and stop with prerequisite error. Resolve path canonically (realpath identity; symlink aliases collapse), reject paths inside fleet projects/backups/cache/staging/sandboxes. Read TOML using tomllib/tomli (no regex fallback). Require a unique `project_id` starting `sbfleet-dev-` (test fixtures use `sbfleet-test-<uuid>`).

Authority binds: full canonical app root, sandbox UUID, exact CLI project ID, authority-relevant config fingerprint, CLI version, migration mode, owned network id, inventoried resources. Short `path_hash` is a readable Docker/FS name only — not sole identity; short-hash collisions refuse. Global uniqueness index path is `sandboxes/index/by-project-id/<sha256(project_id)>` (never raw project ID in the path). Adoption + index are one crash-consistent pair under registry then per-sandbox locks; inconsistent/interrupted journal state fails closed (no silent overwrite).

Ordinary `start`/`reset`/`destroy`/`env` refuse authority fingerprint drift. Only `sandbox start PATH --revalidate` may update the fingerprint after classifying drift and re-running full checks under lock. **CLI `project_id` is immutable after adoption** — if `config.toml` changes the ID, refuse and require destroy/re-adopt (new identity); `--revalidate` must not transfer or overwrite another sandbox's project-ID index. Do not silently take over foreign same-name Docker resources.

Authority-relevant config/dotenv/linked-state/migration-mode facts are **re-read under** `registry → sandbox` locks immediately before dispatch (pre-lock work may only locate the lock). Concurrent edits while waiting for the lock cannot authorize from a stale snapshot.

Before **start**/reset/stop/destroy/env, observe containers, network, and volumes **independently** (PRESENT_AND_OWNED / CONFIRMED_ABSENT / PRESENT_BUT_FOREIGN / UNKNOWN). Ownership is separate from runtime state (RUNNING / STOPPED / MIXED / UNKNOWN / ABSENT). Action predicates: start may dispatch when containers are confirmed absent and network/volumes are absent or owned (official stopped shape); already PRESENT_AND_OWNED resources return the supported idempotent success **only when all required containers are actually RUNNING** with exact owned network name plus attachment NetworkID equal to the positively inspected canonical full network Id (stored short >=12-hex IDs may resolve via inspect; attachment proof never uses arbitrary prefix matching) and loopback bindings — retained exited or mixed RUNNING/EXITED never count as already-running (truthful nonzero refuse, zero CLI start); stop may be idempotent when containers are confirmed absent; destroy may proceed with absent containers but must prove ownership or confirmed absence for network and volumes (recorded names are comparison evidence only); reset and env require PRESENT_AND_OWNED **RUNNING** runtime resources — confirmed absence does not authorize `db reset --local` or env child spawn. UNKNOWN/foreign in any class refuses with **zero** official CLI start/stop/destroy dispatch. After a failed post-start invent/binding proof, cleanup is limited to **attempt-delta** positively owned resources (`post_owned − pre_owned`); pre-existing owned network/volumes/containers survive; foreign/unknown resources are left untouched — never fall back to broad `stop --project-id`. Destroy re-enumerates the full CLI project namespace afterward and returns nonzero if owned residuals remain. Do not remove all supabase-looking resources or use stop --all / prune.

## Credential and target guards on EVERY call

1. Explicit `--workdir <canonical app path>`; do not depend on ambient cwd. Reject `supabase/.temp/project-ref` and other linked remote cache indicators, `[remotes]` definitions, Cloud-style env references, symlinked config or alternate config roots. Do not delete user's linked state to make guards pass.
2. Child environment is allowlisted (PATH, necessary locale/temp, local Docker socket settings only). Remove inherited SUPABASE_*, PG*, DATABASE_URL, Cloud/provider tokens and remote Docker variables; add only documented guard values. Set `SUPABASE_HOME=<private per-sandbox cli-home>`, `SUPABASE_NO_KEYRING=1`, `SUPABASE_TELEMETRY_DISABLED=1`, `DO_NOT_TRACK=1`, `SUPABASE_EXPERIMENTAL_STACK=0`. Do not repurpose the user's HOME. Verify private CLI home contains no access-token/profile credentials.
3. CLI can load root/ancestor and supabase `.env`, `.env.local` and environment-selected files. Audit every dotenv location reachable by the pinned CLI resolver before invocation. Supported authority dotenv grammar is exact (`KEY=value` / `export KEY=value`, optional quotes, blanks/comments); malformed lines refuse. Refuse access tokens, remote URL/password/project selectors, libpq/Docker/Compose targeting variables and ambiguous dotenv parsing in those files. Do not copy Cloud credentials into isolated home. Set `SUPABASE_ACCESS_TOKEN` in the child to a deliberately invalid nonsecret sentinel to prevent dotenv/keyring fallback even if a future path is missed; this is not a credential. Also force a loopback invalid Management API endpoint if supported by the pinned settings layer (`SUPABASE_API_URL=http://127.0.0.1:9`); local operations must still pass acceptance. No API requests are needed.
4. Construct only fixed argv for init guidance/start/status/stop/reset. Reject wrapper input resembling --linked, --db-url, --project-ref, --all, login/link, remote project selection or arbitrary tail flags. `--yes` only answers the wrapper's local destructive confirmation, never broad upstream remote permission.
5. Recheck config fingerprint immediately before mutations under lock. Docker context must be local. Config env() references are allowed only for explicit app-local non-Cloud settings supplied through audited local files; unresolved/security-related references fail closed. Refuse mounted functions outside app tree (entrypoint/import_map containment) and app files carrying production credentials in wrapper-controlled env execution. HTTP/API/Studio URLs must be loopback http(s) without userinfo. PostgreSQL URLs must match the pinned CLI 2.118.0 local form; query parameters are allowlist-empty (any query including `host`/`hostaddr`/`port`/`service`/`servicefile` refuses).

These controls protect the documented wrapper workflow, not an adversarial agent. Same-user file/Docker access bypasses it. Strongest deployment: dedicated dev OS user or VM with its own Docker daemon and no access to fleet root, production .env, native keyring or Cloud credentials. Never claim environment scrubbing is perfect sandboxing.

## Network and command mapping

Create only the owned bridge network with labels `io.sbfleet.sandbox=<path-hash>`, `io.sbfleet.sandbox_uuid=<uuid>`, and `-o com.docker.network.bridge.host_binding_ipv4=127.0.0.1`. Inspect existing network ownership/options before reuse/delete; refuse host/overlay/shared unowned networks; never relabel foreign networks. Static TOML/port preflight runs before CLI start; after resources exist, inspect effective published HostIp immediately and fail closed before returning success. Post-start inspection is **not** proof that no temporary exposure was possible.

- `sandbox start PATH [--migration-mode supabase|external] [--revalidate]`: live ownership preflight for existing adoption; then `supabase --workdir PATH --network-id NETWORK start`. No invented --local. Inventory owned containers/volumes after start; on post-start ownership/binding failure, remove only attempt-delta positively owned resources (never broad project-id stop). Ordinary wrapper output is a sanitized summary — not raw CLI stdout/stderr (credentials may appear in CLI output).
- `sandbox status PATH`: official status `--output json`, parsed privately; return only local health/URLs/project_id, never keys. Non-running is STOPPED, not a command crash. Refuses on fingerprint drift.
- `sandbox stop PATH`: `supabase --workdir PATH stop --project-id ID`. Data preserved.
- `sandbox reset PATH --yes`: `supabase --workdir PATH --network-id NETWORK db reset --local`; ownership/locality gates; reinspect afterward. No --db-url ever.
- `sandbox destroy PATH --yes`: prove per-class live ownership/absence; stop `--no-backup` only when containers present+owned; remove only proven-owned volumes and owned network; full-namespace reinspect; nonzero on residuals; never broaden cleanup / never use recorded names as authority after invent failure. Keep application source.
- `sandbox studio PATH`: parse STUDIO_URL with HTTP locality (loopback, no userinfo); refuse secret query parameters.
- `sandbox env PATH -- COMMAND`: no spawn unless adoption valid, live resources PRESENT_AND_OWNED, status succeeded, endpoints verified local; inject only local DATABASE_URL/SUPABASE_URL/keys; preserve child argv; child signal exits map to `128+signal`. Explicit child stdio is intentional.

PATH is **required** (no default to cwd). Interactive active long-lived project does not alter it. User files are never deleted.
## A: Supabase SQL migrations

In a disposable app repository under the dedicated dev account:

```sh
supabase init
# Set config.toml project_id to a unique sbfleet-dev-... value.
sbfleet sandbox start .
supabase migration new add_recipes
# Edit supabase/migrations/<timestamp>_add_recipes.sql and seed.sql.
sbfleet sandbox reset . --yes
supabase gen types --lang typescript --local > src/database.types.ts
sbfleet sandbox studio .
sbfleet sandbox destroy . --yes
```

Direct official CLI examples must run under the same isolated credential/network policy (dedicated account is recommended); they are not a wrapper enforcement claim. Do not run login/link. Start on a fresh volume may apply app migrations/roles/seed, which is expected in this mode. Configure ports in config.toml if another sandbox already uses defaults. App config remains app-owned.

## B: Drizzle (external migration mode)

Initialize config and unique project_id once. Set `[db.migrations] enabled = false` and `[db.seed] enabled = false`. Application migration SQL files may legitimately exist; sbfleet does not require those directories to be empty. Wrapper refuses external mode if Supabase automatic migrations/seed remain enabled; record `migration_mode:"external"` via `sandbox start --migration-mode external`. The default mode is `supabase`; mode changes require stopped sandbox and explicit selection.

```sh
sbfleet sandbox start . --migration-mode external
sbfleet sandbox env . -- bun run db:migrate
sbfleet sandbox studio .
sbfleet sandbox reset . --yes
sbfleet sandbox env . -- bun run db:migrate
```

Reset restores the local backend's own baseline; it does not run Drizzle. App explicitly applies its own migrations afterward. Prisma/plain SQL can use the same local env mechanism. Never transfer production secrets or customer data automatically into a sandbox.

## Self-hosted migrations are a separate operator action

`env myapp --admin -- bun run db:migrate` targets a long-lived project, grants real admin access and is not part of autonomous sandbox permission. Runtime clients should use least-privileged app roles. Official `migration up --db-url`/`db push --db-url` are available for operators using SQL migrations, but sbfleet does not force them or generate secret-bearing URL arguments. Types can use explicit local CLI --local during app development. No Cloud credentials are needed for direct self-hosted DB connections.
