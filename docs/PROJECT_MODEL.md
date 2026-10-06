# Filesystem project model

## Identity and layout

Data root precedence: `--home ABSOLUTE_PATH`, `SBFLEET_HOME`, `$XDG_DATA_HOME/sbfleet`, `$HOME/.local/share/sbfleet`. Canonicalize once; refuse symlinked projects, world-writable ancestors within the managed root, unsupported NFS locking and another owner's root. No runtime data belongs in this source repository.

```text
SBFLEET_HOME/                         mode 0700
  fleet.json                         format_version, fleet_id, public age recipients
  locks/registry.lock
  locks/<project-uuid>.lock
  projects/<slug>/
    project.json                     mode 0600; no secrets
    operation.json                   current/recent journal, redacted
    deployment/                      upstream docker/ copy, mode 0700
      .env                           mode 0600
      .supabase-version
      docker-compose.override.yml    generated, mode 0600
      volumes/db/data/                PostgreSQL-owned UID/GID
      volumes/storage/               upstream container-owned UID/GID
      volumes/functions/
      volumes/snippets/
    generated/nginx.conf
  backups/<project-uuid>/<backup-id>.tar.age
  backups/<project-uuid>/<backup-id>.json  nonsecret ciphertext receipt
  cache/upstream/<sha>/               immutable official snapshot
  staging/<operation-uuid>/           private partial operations
  sandboxes/<path-hash>/              ownership, CLI home, lock, no app source copy
```

Slug: ASCII `[a-z][a-z0-9-]{0,30}[a-z0-9]` or a single letter; max 32, no trailing hyphen, no reserved `all`, no path separators, whitespace, Unicode folding or option-looking input. Display name: 1–100 printable characters without control sequences; JSON output escapes correctly. UUID4 immutable project id plus fleet UUID provide Docker identity `sbfleet-<fleet12>-<project12>`; check full metadata ownership and collision before creation. Do not derive deletion authority from the slug alone. Never reuse another root's fleet UUID accidentally; copied roots fail ownership checks until explicitly recovered.

## Metadata schema v1

`project.json` requires: `format_version:1`, `id` UUID, `fleet_id`, `slug`, `display_name`, UTC RFC3339 `created_at`, `profile:"standard"`, `compose_project`, `ports:{gateway,db_direct,pooler_session,pooler_transaction}` (four distinct integers), `domain:null|hostname`, `public_url`, `upstream:{ref,sha}`, `last_verified_upstream:null|{ref,sha,at}`, `image_digests:{service:repo_digest}`, `creation_complete:boolean`. Domain is hostname only, no credentials/path/port/wildcard; use conservative DNS label validation and reject nginx metacharacters. V1 domain URL is HTTPS; no domain means loopback HTTP. `SITE_URL` is a separate application redirect URL in .env, never inferred to be the Studio URL.

Optional (backward compatible when absent):

- `branding.organization_name` / `branding.project_name` — Studio display labels (`STUDIO_DEFAULT_*`); defaults remain upstream `Default Organization` / `Default Project`
- `site_url` — application origin for Auth redirects (`SITE_URL`); when omitted, create falls back to `public_url` (loopback-friendly)
- `additional_redirect_urls` — list merged into `ADDITIONAL_REDIRECT_URLS` (comma-separated in `.env`)
- `google_oauth_enabled` — sets `GOOGLE_ENABLED`; client id/secret stay only in `deployment/.env`, never in `project.json`

`public_url` is the public Supabase/API host (e.g. `https://auth.example.com`). Generated `API_EXTERNAL_URL` is always `${public_url}/auth/v1` with exactly one `/auth/v1` segment. Google callback is `${API_EXTERNAL_URL}/callback`. Studio names do **not** change OAuth hostnames.

Optional `last_backup_id` is only a lookup hint; validate the receipt/archive. Never store passwords, JWTs, private keys, DB URLs with credentials or fabricated cached health. Secrets live only in .env or encrypted backups. Unknown schema versions fail with an actionable error; preserve unknown files. Atomically write JSON via same-directory tempfile, fsync and rename; fsync directory. Limits on file size/types defend malformed metadata. No arbitrary migrations of old metadata in V1.

Named volumes are Compose-scoped db-config (durable pgsodium key) and deno-cache (disposable). Project directories are the registry; fleet.json contains only root identity/settings, never project rows. Backups are outside project directories and survive remove by default.

## Locking and partial operations

Registry lock precedes project lock whenever both are needed; never acquire in reverse order. Registry lock protects slug/port reservations and final registry changes. Project lock covers any lifecycle, update, backup, restore, env execution or deletion. Use flock with bounded wait, PID/operation diagnostics, no unlink-on-unlock races; lock files open with no-follow semantics and refuse symlink/non-regular targets. Kernel locks release on process death; journal remains. Root/fleet initialization serializes `fleet.json` creation under the registry lock. Long logs/status do not hold mutation locks; report an in-flight operation. Nested helpers called from an already-locked maintenance transaction use `already_locked=True` rather than reacquiring the project lock.

Create under `projects/<slug>` only after reserving it under registry lock; immediately write `creation_complete:false` and `CREATING` intent. Stage vendor/config changes privately. Finalize files and metadata only after config/secret/ownership validation. With --start, health failure records FAILED and preserves data; keep creation_complete=false until the requested first start passes health, so --resume is available. Without --start, valid config sets creation_complete=true and yields CREATED/STOPPED. Interrupted creation is visible as incomplete, never hidden as healthy. `create <slug> --resume` accepts only the same incomplete owned record, reuses existing secrets/ports, reconciles resources, and never resets data. `remove` can clean a proven-owned partial project with explicit no-backup acknowledgement if no usable DB exists. Unknown partial contents are retained for inspection.
