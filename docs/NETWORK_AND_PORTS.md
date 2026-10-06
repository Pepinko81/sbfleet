# Isolation and exposure contract

## Actual upstream collisions and resolutions

- Top-level `name: supabase`: override with metadata's unique Compose name in the generated override AND explicit sanitized COMPOSE_PROJECT_NAME for every script/Compose call.
- All 11 services have fixed container names: render `<compose_project>-<service>` for studio, api-gw, auth, rest, realtime, storage, imgproxy, meta, functions, db, supavisor. Do not leave any default name. Add `io.sbfleet.fleet`, `io.sbfleet.project` and `io.sbfleet.operation` labels (operation only for transient helpers).
- Realtime's upstream name is also used in Envoy DNS and host rewrites: add private network alias `realtime-dev.supabase-realtime`. Keep the upstream `realtime-dev` tenant and HTTP host rewrite unchanged; these are internal to separate DBs/networks. Merely renaming that container would break routing.
- Base has no explicit external/global network name. Default becomes `<compose_project>_default`. Add ownership labels. Service aliases `db`, `auth`, `studio`, `kong`, `envoy`, etc. are safe only on that distinct network. No shared application network.
- Base db-config and deno-cache have no explicit global `name:` or `external:`. Compose scopes them. Add ownership labels; always inspect actual mount names and labels before backup/removal.
- All base host bind mounts are relative `./volumes/...`; resolve from the per-project deployment directory. Reject escaped/symlinked mounts. Container-side absolute paths are expected, not host collisions. Copy vendor configuration, never share writable bind data.
- Gateway publishes 8000 by default; Supavisor publishes POSTGRES_PORT→5432 and transaction port→6543. Base does not publish DB directly or Studio. Override **whole port lists** to four loopback ports as below. Keep internal POSTGRES_PORT=5432; changing it to allocate host ports would also change internal DB connections.
- Optional logs mounts `/var/run/docker.sock`, uses fixed Vector container-name routing and can observe other projects. Not enabled or supported in V1. Base has no Docker socket mount.
- Optional nginx/caddy publish host 80/443 and have fixed names; not enabled. Host nginx is separate. S3/RustFS/PgBouncer/PG15/dev overrides are not accepted V1 inputs. The dev file adds host ports and anonymous data volumes, so reset.sh is unsafe for fleet use.
- `.env`, stamps, config backups and script cwd assumptions are isolated by deployment directory. update staging/promotion preserves the fleet override; no global working copy or shared secrets.

## Exact generated overlay shape

The following is a specification fragment; renderer must expand ALL 11 service names and labels, not copy only this fragment:

```yaml
name: <compose_project>
services:
  api-gw:
    container_name: <compose_project>-api-gw
    ports: !override
      - "127.0.0.1:<gateway>:8000/tcp"
  db:
    container_name: <compose_project>-db
    ports: !override
      - "127.0.0.1:<db_direct>:5432/tcp"
  supavisor:
    container_name: <compose_project>-supavisor
    ports: !override
      - "127.0.0.1:<pooler_session>:5432/tcp"
      - "127.0.0.1:<pooler_transaction>:6543/tcp"
  realtime:
    container_name: <compose_project>-realtime
    networks:
      default:
        aliases: [realtime-dev.supabase-realtime]
    environment:
      API_JWT_JWKS: ${JWT_JWKS}
  auth:
    environment:
      GOTRUE_JWT_KEYS: ${JWT_KEYS}
  storage:
    environment:
      JWT_JWKS: ${JWT_JWKS}
  functions:
    environment:
      SUPABASE_JWKS: ${JWT_JWKS}
```

Persist `COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml`, `COMPOSE_PATH_SEPARATOR=:`, and COMPOSE_PROJECT_NAME in .env. Clear inherited Compose/env override inputs; supply these exact values to child processes. Do not let automatic default override discovery choose files. Add labels to services, default network and both volumes. Preserve all upstream image tags, dependencies, commands and gateway aliases.

Before start/update inspect resolved Compose JSON in memory: exact service inventory and image compatibility; correct unique container names and labels; only the four expected 127.0.0.1 bindings; correct targets; one private owned default network; no external resources, host network, privileged services, socket mounts or mount escapes. Unknown upstream services require a reviewed compatibility adapter, never automatic generic rewriting.

## Allocation and races

Default candidate range 20000–39999; configurable valid unprivileged range, no count cap. Under registry lock read all project reservations, including stopped/incomplete projects. Bind temporary IPv4 loopback TCP sockets for four free candidates; also inspect existing Docker published ports and wildcard listeners. Persist reservation before releasing sockets/lock. At start reacquire registry then project lock, validate/bind-check ports (accept only verified selected containers already owning bindings), then release probe sockets immediately before Compose starts. Retain registry lock through Docker binding outcome. Never silently renumber an existing project.

There is inevitably a race with unrelated processes after socket release: Docker's bind failure is authoritative, abort and record FAILED; don't claim atomic reservation across the entire OS. Concurrent sbfleet operations under one root cannot double-allocate; distinct roots/users rely on OS bind failure. Exhaustion is actionable, not an artificial project limit. Test contention, IPv4 wildcard and IPv6 dual-stack listeners.

No DB/public IPv6 binds. Direct DB is loopback for migration/admin access, pooler session/transaction are distinct loopback ports for **host-side** apps. Loopback is not access control against local users. Reject remote Docker endpoints/contexts because localhost paths and probes would be wrong. Status uses Docker inspect plus SQL/HTTP, not port-open alone.

**Application deployment modes (V1):**

| Mode | Status |
|------|--------|
| Application process on the Linux host → `127.0.0.1:<allocated port>` | **Supported** — `sbfleet connection` / `env --admin` |
| Application in another Docker container on the same host | **Not supported in V1** — loopback HostIp is not reachable as `127.0.0.1` inside that container; no shared app network; do not auto-attach foreign containers or publish `0.0.0.0` |
| Application on another machine (remote PostgreSQL) | **Not supported by default** |

Operators must not use `docker ps` as the connection source of truth — use `sbfleet connection PROJECT`.
