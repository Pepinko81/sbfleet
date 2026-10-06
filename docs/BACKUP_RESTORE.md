# V1 encrypted cold backup and restore

> **STATUS:** Cold backup issues `verification=recovery` only after the **mandatory production verifier contract** (`recovery-verify/v3`) succeeds — including snapshot-bound `source_facts` (writer-quiesced, PG up), source-bound Vault/pgsodium proof, Auth schema + source-bound user-count viability, required DBs/roles/grants, Storage evidence, `SELECT 1`, and `source == manifest == recovered` functions/snippets. Same-project restore **recovery-verifies the requested archive** after structural prevalidation and **before** pre-restore backup / stop / quarantine; refuses cross-pin restore. Default remove requires a currently usable bound recovery archive (not a string-only sidecar). Cleanup failures surface exact residuals without destroying a valid archive. Capacity is budgeted **per filesystem** (UNKNOWN fail-closed). Age decrypt provides ciphertext confidentiality/integrity — not cryptographic source provenance. `--recover` (absent project) and `backup all` remain unsupported.

## Chosen recovery contract

V1 uses a **clean-shutdown physical PostgreSQL cluster backup**, with Storage frozen in the same maintenance window. This is deliberately offline and **same-pin** (exact recorded upstream ref+SHA and image/platform facts). It is not a live PGDATA tar, pg_dump-only export, PITR system, major-version migration mechanism, or whole-version vendor rollback. Cross-ref / cross-SHA restore is refused. Small personal projects can accept downtime. `pg_controldata` from the exact database image must prove clean shutdown before copying.

Official upstream PG upgrade documentation identifies both db/data and db-config/pgsodium_root.key as recovery-critical. The supported standard/storage-enabled deployment additionally requires **all** file-backend Storage objects. Remote S3 backends, external tablespaces/WAL directories, custom mounts and user-defined external data paths are refused as unsupported before backup.

An archive is portable only to a compatible Linux Docker host architecture with the exact recorded upstream/image set. Cross-major or cross-architecture restores are not promised. Missing pinned images is WAITING_EXTERNAL, never permission to restore into a different image. Physical restored credentials remain those of the same project identity; this is recovery, not a clone-project feature.

**Interrupted update interaction:** A pre-update recovery archive remains valuable evidence/data protection. While an unresolved `UPDATING` journal exists, ordinary restore is refused. After configuration promotion (destination pin may already differ from the archive), **direct same-pin restore into that promoted destination is unsupported**. Use `update --reconcile --operation-id` for the reviewed edge when a promote-record exists. sbfleet does not claim generic cross-version rollback.

## Units and archive format 1

Outer `<uuid>.tar.age` plus nonsecret JSON receipt (format version, backup id, project UUID/slug, timestamp, ciphertext SHA256/size, verification level, optional recovery evidence). Public receipt is not authentication; age integrity and internal checksums are mandatory. When both receipt and archive exist, receipt/archive binding is verified.

Encrypted tar members:

- `manifest.json`: format_version=1, backup_id, created_at UTC, project UUID/slug/fleet, profile standard, upstream ref+SHA, per-service image facts, platform/architecture, PG version/control facts, clean shutdown evidence, prior running/stopped state, method `cold-physical`, storage backend `file`, inventory relative-path SHA256+size+type entries for every regular member (manifest itself excluded from inventory checksum list).
- `postgres/`: complete clean PGDATA, including pg_wal and global catalogs.
- `db-config/`: entire owned named volume, notably pgsodium_root.key.
- `storage/`: complete deployment/volumes/storage tree.
- `deployment/`: `.env`, `.supabase-version`, functions, snippets and generated override for diagnosis.
- `project.json`: source identity evidence only — never blindly replaces destination fleet metadata.

Fail-closed extractor refuses absolute paths, `..`, symlinks, hardlinks, device nodes, FIFOs, sockets, duplicates, and expansion beyond budget. Safety does not depend on Python tar defaults.

## Locked backup primitive

`create_backup` acquires mutation authority once and delegates to `_create_backup_locked`. `restore_backup` authorizes restore, runs decrypt/prevalidation/disposable recovery verification **without** `begin_operation`, then begins a durable RESTORING journal only immediately before `_create_backup_locked(pre_restore=True)` (first target-mutation boundary). Nested stop/start use `already_locked=True` and `manage_journal=False`. Pre-mutation refusals must not leave a blocking RESTORING journal; post-boundary failures remain blocking.

## Disposable recovery verification

Backup-time verification uses a **minimal isolated** environment and returns `RecoveryVerificationResult` under verifier contract `recovery-verify/v3`. Capture ordering is snapshot-consistent: lock → capacity preflight → stop non-DB writers (PostgreSQL remains up) → capture `source_facts` + Vault challenge + functions/snippets inventory → cleanly stop PostgreSQL → cold archive. Mandatory production assertions (all participate in `hard_ok`): PostgreSQL readiness, `SELECT 1`, databases/roles/login/membership/grant facts equal to source, Auth relation presence + source-bound user-count viability (read-only; no Auth mutation), Storage tree evidence, source-bound Vault/pgsodium crypto, and `source inventory == manifest inventory == recovered inventory` for functions/snippets. Acceptance `expected_*` fixtures may add probes but cannot create a stronger recovery level than this production path. Weaker levels (`decrypt_structural`) and legacy `recovery-verify/v2` receipts cannot authorize remove, restore destructive swap, or update.

## Exact backup ordering

1. Lock project; capture prior HEALTHY/STOPPED; disk preflight (per-filesystem capacity; UNKNOWN size/free/identity refuses) **before** downtime.
2. Writer quiesce; capture source-bound crypto + recovery facts (including functions inventory and Auth counts) while DB reachable; stop PostgreSQL; `pg_controldata` clean shutdown.
3. Collect required units fail-closed; stream hashes; age-encrypt; two-phase decrypt verify + disposable recovery verification consuming `source_facts`.
4. Publish receipt (`recovery` only after verifier ok); wipe plaintext staging (cleanup failure surfaces residuals; archive preserved); restore prior running state for top-level backups (STOPPED left stopped).

## Restore ordering

1. Decrypt; **inspect `manifest.json` without extraction**; build exact expected inventory; `safe_extract(expected=…)`; validate identity/`.env`/required files; establish destination **authoritative** same-pin facts — all **before** target mutation.
2. Capacity preflight; **disposable recovery verification of the requested extracted payload** under `recovery-verify/v3` — refuse before any stop/quarantine when it fails.
3. Recovery-verified pre-restore backup under same restore lock/journal (proves current target, not the requested archive).
4. Quarantine current units; install recovered data; ownership verify; reconcile destination; revalidate authority; start; RESTORED only after HEALTHY; wipe decrypted staging on success (residuals observable).
5. Failure retains quarantine and journal; no automatic destructive rollback.

## Restore destination reconciliation

Archived `.env` is never copied wholesale. Source recovery material (JWT/Postgres/Vault/crypto keys, `POOLER_TENANT_ID`, …) is merged with destination-owned placement/authority fields (Compose selectors, ports, URLs, dashboard username). After reconciliation, Run 2A authority/Compose validation is re-run before start.

`--recover` absent-project recovery remains unsupported. Default remove requires `require_recovery_backup` (usable archive + current contract evidence); `--no-backup` remains the explicit bypass.
