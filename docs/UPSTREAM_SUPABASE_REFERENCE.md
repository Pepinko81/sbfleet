# Upstream evidence and compatibility baseline

Inspected 2026-09-26 (Europe/Berlin). Repository: https://github.com/supabase/supabase. Latest stable numeric self-hosted tag discovered using remote tags: **self-hosted/v0.8.2**. Annotated tag object `47111f95a43ffcc20ab288e29c48ce0b80174bd6`; peeled commit **564eab8ad7840b13324f68b1bfac074ef8d51c21**, committed 2026-09-23. This is a release snapshot, not master. Official setup/update scripts select `self-hosted/v*`; sbfleet accepts stable numeric tags only, resolves SHA and forbids their HEAD/master fallback.

Optional reference sparse clone: `$HOME/.cache/sbfleet/upstream/supabase` (or any cache path). Implementers need not have this path: fetch the exact official commit and materialize docker/. No reference clone is part of the SBfleet repository.

## Files inspected

All following links are immutable at the inspected commit:

- [docker/README.md](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/README.md): deployment ownership, official lifecycle links. Its service summary still mentions logs although those are now optional; actual Compose is authoritative.
- [docker-compose.yml](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/docker-compose.yml): all 11 services, images, mounts, healthchecks, ports and dependencies reviewed.
- [.env.example](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/.env.example): COMPOSE_FILE, secrets, JWT/JWKS, internal POSTGRES_PORT, URL and tenant settings.
- [run.sh](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/run.sh), [setup.sh](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/setup.sh), [update.sh](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/update.sh), [reset.sh](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/reset.sh): full script behavior inspected.
- [CONFIG.md](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/CONFIG.md): introduction and relevant Studio/Auth/DB/pooler/security settings inspected. This upstream document itself warns that explanatory prose is partly synthesized and not independently canonical; don't elevate it above actual service wiring.
- [override directory](https://github.com/supabase/supabase/tree/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker): docker-compose.envoy.yml, kong.yml, logs.yml, nginx.yml, caddy.yml, pg15.yml, pg17.yml, pgbouncer.yml, s3.yml, rustfs.yml and dev/docker-compose.dev.yml reviewed. Also .gitignore, upgrades.json, CHANGELOG/version metadata.
- [volumes/api/envoy](https://github.com/supabase/supabase/tree/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/volumes/api/envoy): envoy.yaml, cds.yaml, lds.template.yaml routes/auth sections and docker-entrypoint.sh. Also volumes/logs/vector.yml name routing and volumes/proxy/nginx/supabase-nginx.conf.tpl.
- [utils/generate-keys.sh](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/utils/generate-keys.sh), [utils/add-new-auth-keys.sh](https://github.com/supabase/supabase/blob/564eab8ad7840b13324f68b1bfac074ef8d51c21/docker/utils/add-new-auth-keys.sh): outputs, prerequisites, .env.old and Compose mutation.

## Concrete findings

Base service dependencies: api-gw waits for Studio; auth/rest/realtime/meta/db consumers depend on healthy DB; Storage additionally needs REST and imgproxy; functions waits for api-gw; Supavisor waits for DB. Base Studio has no analytics dependency. All base services are retained; unsupported pruning would leave gateway routes/features dangling.

Images include Postgres `supabase/postgres:17.6.1.136`, Studio `2026.09.07-sha-7996410`, Envoy `v1.39.1`, GoTrue `v2.196.0`, PostgREST `v14.17`, Realtime `v2.134.10`, Storage `v1.74.0`, imgproxy `v3.31.4`, postgres-meta `v0.99.0`, edge-runtime `v1.76.2`, Supavisor `2.9.12`. Pin snapshot and record runtime digests; tags alone are not cryptographic immutability.

Base `name: supabase` and all container names are fixed. Default network and named volumes are not explicitly globally named, but inherit that Compose identity. Service DNS aliases are network-local. Realtime is special: Envoy connects to `realtime-dev.supabase-realtime` and rewrites Host to that value. Add this alias when giving the container a unique name. Full collision-to-resolution inventory is locked in NETWORK_AND_PORTS.

Gateway HTTP publishes `${API_GW_HTTP_PORT:-${KONG_HTTP_PORT:-8000}}:8000/tcp` without host IP. Supavisor publishes `${POSTGRES_PORT}:5432` and `${POOLER_PROXY_PORT_TRANSACTION}:6543`; POSTGRES_PORT is also internal DB configuration. No base direct DB or Studio host port. Relative storage bind is `volumes/storage`; PostgreSQL bind is `volumes/db/data`; named db-config holds the pgsodium root key. Functions/snippets are additional mutable binds; deno-cache is reconstructible. There are no host-absolute binds in the base. The logs override adds the host Docker socket and fixed-name log filters: reject it for V1.

Envoy routes APIs and Studio together, performs dashboard Basic authentication, API-key translation and Realtime websocket routing. Its admin listener is container-loopback 9901. Studio uses project-local meta/DB and upstream `/project/default`; no custom GUI needed. Public Auth callback base now includes `/auth/v1`. Host nginx can forward all paths unchanged to the gateway; it need not reproduce the upstream container nginx template's split direct-Studio routing.

run.sh changes cwd to its own directory, relies on native COMPOSE_FILE, supports up --wait, down, restart, recreate, pull, status, logs and config management. secrets/printenv/compose-config expose credentials; never forward their output normally. stop does not delete volumes unless callers pass unsafe flags. reset.sh explicitly layers dev Compose, calls down -v --remove-orphans and recursively removes binds: do not use it.

setup.sh can install host packages/Docker and fall back to sudo. It supports --ref/--skip-deps/--yes, copies docker/, generates keys, writes `.supabase-version` in `ref=...` form and pulls images. It does not supply fleet isolation before that pull. sbfleet uses exact snapshot copy plus its generators, not the all-in-one bootstrap.

Both key scripts print secret values. generate-keys writes .env and leaves .env.old. add-new-auth-keys needs Node>=16 or unpinned node:22-alpine via Docker; generates asymmetric keys plus opaque API keys, writes .env and uncomments four Compose environment lines, leaving .old files. Run both in private staging with captured/discarded output, then copy only validated .env and place equivalent environment entries in the generated overlay.

update.sh fetches base/target snapshots, uses three-way git merge-file, excludes target .gitignore paths, retains removed-upstream files, appends missing .env defaults, and uses upgrades.json as a manual-action gate. Its config .tgz includes .env and excludes only DB/storage/backups. Backup errors are warnings. Conflicts exit 2 and do not stamp; dry-run exits 0 even when its report contains conflicts. Successful merge stamps BEFORE pull/recreate/health. A changed updater is staged as update.sh.dist, not installed. Consequently exit 0 is not UPDATED. See UPDATE_STRATEGY for containment, verification and promotion.

## Official documentation checked

Live pages checked on the inspection date; corresponding self-hosting/local-development MDX was also inspected in the pinned repository where available:

- https://supabase.com/docs/guides/self-hosting/docker
- https://supabase.com/docs/guides/self-hosting/updating
- https://supabase.com/docs/guides/self-hosting/self-hosted-auth-keys
- https://supabase.com/docs/guides/self-hosting/accessing-postgres
- https://supabase.com/docs/guides/self-hosting/postgres-upgrade-17
- https://supabase.com/docs/guides/self-hosting/restore-from-platform
- https://supabase.com/docs/guides/local-development
- https://supabase.com/docs/guides/local-development/cli/getting-started
- https://supabase.com/docs/guides/local-development/managing-config
- https://supabase.com/docs/guides/local-development/database-migrations
- https://supabase.com/docs/reference/cli/introduction (init/start/stop/status/reset/gen types/migration up/db push/db URL flags)

The restore-from-platform page contains stale PG15 wording compared with current PG17 Compose. Platform migration recipes are not a complete self-hosted disaster-recovery specification. In particular pg_dump alone omits Storage bytes and external encryption keys; CLI db dump applies filtering to managed schemas. Do not use that as the fleet backup implementation.

## CLI evidence and extra source inspection

Official CLI repository https://github.com/supabase/cli, latest stable numeric tag inspected **v2.118.0**, commit **70b42b8bf64b8cf1fd14c02c013d99dd655626e2**. Source inspection was necessary because docs do not fully specify dotenv, credential isolation and experimental-backend selection. Optional sparse reference clone may live under `$HOME/.cache/sbfleet/upstream/cli`.

Inspected `apps/cli/src/commands/{start,stop,status,db/reset}/SIDE_EFFECTS.md`, start/reset handlers and tests, shared/config/cli-settings.layer.ts, supabase-home tests, CLI README, plus `apps/cli-go/internal/utils/access_token.go`, project-ref/config paths and migration application guards. At this tag CLI includes TS and Go code; do not assume old Go source paths or semantics.

init creates app-local supabase/config.toml. start/status/stop are local commands and have no `--local` flag; never invent one. Reset must explicitly use `db reset --local`; `--linked` and `--db-url` enable destructive remote targets. Stop --no-backup destroys local volumes; --all affects multiple local projects and is forbidden. Stop --project-id selects local identity. Status JSON/env may contain keys: parse privately and whitelist output. `gen types --local` and `migration up --local` are supported. db push/migration up can use a direct --db-url for self-hosted databases without Cloud linking; sbfleet sandbox never forwards that flag.

Fresh-volume start can run migrations, roles and seeds. `[db.migrations] enabled=false` and `[db.seed] enabled=false` are required for external migration ownership; app code explicitly invokes Drizzle after start/reset. No automatic external hooks.

Login credentials may reside in native keyring or ~/.supabase/access-token. Current source supports SUPABASE_HOME and SUPABASE_NO_KEYRING; current CLI also reads project-root and supabase dotenv files. Set isolated SUPABASE_HOME, disable keyring, reject linked/temp state and credential-bearing dotenv, scrub override variables and force SUPABASE_EXPERIMENTAL_STACK=0. The new experimental stack is outside V1 compatibility. A wrapper is not an OS security sandbox.

The inspected CLI start service builders publish hostPort/containerPort without a forced HostIp (studio.service.ts, kong.service.ts, supavisor.service.ts, logflare.service.ts and mailpit.service.ts), consistent with honoring Docker network binding defaults. This is source evidence, not a completed runtime proof. Official local-development networking guidance uses a Docker bridge with `com.docker.network.bridge.host_binding_ipv4=127.0.0.1` and start --network-id. Verify actual published bindings after every lifecycle operation; docs alone don't prove every CLI version honors the network default.

## Planning checks and revalidation

An isolated temporary Compose config-only probe ran with Docker Compose v5.5.1 and Engine 29.7.2 on 2026-09-26. It rendered all 11 unique containers, four correct loopback mappings, scoped default network/db-config/deno-cache and Realtime alias. No containers were started, no images pulled, no user resources changed. This proves Compose merge behavior, not runtime acceptance.

On any new upstream ref re-inspect: service set/dependencies; container/DNS/Host names; every host port/mount/network/volume; key scripts and outputs; gateway auth/routes/Studio; SQL/bootstrap/PG major and db-config; update ignore rules/gates/stamp/self-update/backup behavior; image digests; supported Compose tags. On CLI change reverify flags, dotenv search, credential storage, network bindings, resource deletion selectors, local reset semantics and migration controls. Unknown compatibility fails closed; pinning alone is not approval of new semantics.
