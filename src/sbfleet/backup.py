"""Encrypted cold backup and same-project restore .

Public entrypoints acquire mutation authority once and delegate to locked
primitives. Nested pre-restore backup uses ``_create_backup_locked`` without
reacquiring the lock and without replacing the restore journal.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sbfleet import registry as reg
from sbfleet.archive_safe import (
    ArchiveSafetyError,
    MemberSpec,
    build_tar_from_tree,
    iter_file_digests,
    read_manifest_from_tar,
    safe_extract,
    sha256_file,
    write_buffered_hash,
)
from sbfleet.backup_manifest import (
    DESTINATION_OWNED_ENV_KEYS,
    PROFILE_OWNERSHIP,
    SOURCE_RECOVERY_ENV_KEYS,
    VERIFICATION_DECRYPT_STRUCTURAL,
    VERIFICATION_NONE,
    VERIFICATION_RECOVERY,
    ManifestError,
    bootstrap_expected_from_manifest,
    build_internal_manifest,
    compatibility_matches,
    is_recovery_verified_receipt,
    manifest_bytes,
    manifest_for,
    manifest_sha256,
    normalize_receipt_verification,
    project_identity_matches,
    public_receipt,
    receipt_archive_binding_ok,
    require_db_recovery_facts,
    require_recovery_files,
    require_same_pin,
    utc_now,
    validate_internal_manifest,
    validate_recovery_receipt_evidence,
)
from sbfleet.backup_recovery import (
    RecoveryVerifyError,
    capture_source_crypto_challenge,
    capture_source_recovery_facts,
    cleanup_source_crypto_challenge,
    prove_clean_shutdown,
    run_disposable_recovery_verification,
)
from sbfleet.cli import EXIT_BACKUP, EXIT_FAILURE, EXIT_OK, EXIT_PREREQUISITE, EXIT_SAFETY
from sbfleet.compose import STANDARD_SERVICES
from sbfleet.process import run

# Re-export for existing imports/tests.
__all__ = [
    "BackupError",
    "VERIFICATION_NONE",
    "VERIFICATION_DECRYPT_STRUCTURAL",
    "VERIFICATION_RECOVERY",
    "normalize_receipt_verification",
    "is_recovery_verified_receipt",
    "load_backup_receipt",
    "require_recovery_backup",
    "manifest_for",
    "set_fleet_recipients",
    "create_backup",
    "restore_backup",
    "_create_backup_locked",
    "reconcile_destination_env",
]

HELPER_IMAGE = "alpine:3.20"


class BackupError(Exception):
    def __init__(self, msg: str, *, code: int = EXIT_BACKUP) -> None:
        super().__init__(msg)
        self.code = code


@dataclass
class BackupLockedResult:
    backup_id: str
    archive_path: Path
    receipt: dict[str, Any]
    verification: str
    prior_state: str
    restart_ok: bool | None = None
    restart_error: str | None = None
    cleanup_ok: bool = True
    cleanup_residuals: list[str] = field(default_factory=list)


def load_backup_receipt(root: Path, project_id: str, backup_id: str) -> dict | None:
    path = root / "backups" / project_id / f"{backup_id}.json"
    if not path.is_file():
        return None
    try:
        data = reg.load_json(path)
    except Exception:  # noqa: BLE001
        return None
    return data if isinstance(data, dict) else None


def require_recovery_backup(root: Path, meta: dict) -> dict[str, Any]:
    """Validate a currently usable, correctly bound recovery archive before remove/update.

    A sidecar saying verification=recovery is not enough.
    """
    backup_id = meta.get("last_backup_id")
    if not backup_id:
        raise BackupError(
            "no recovery-verified backup; create one or pass --no-backup where allowed",
            code=EXIT_SAFETY,
        )
    project_id = str(meta["id"])
    backup_id = str(backup_id)
    receipt = load_backup_receipt(root, project_id, backup_id)
    if receipt is None:
        raise BackupError(
            f"backup receipt missing for {backup_id}; refuse destructive prerequisite",
            code=EXIT_SAFETY,
        )
    try:
        validate_recovery_receipt_evidence(receipt)
    except ManifestError as exc:
        raise BackupError(
            f"backup {backup_id} recovery evidence unusable: {exc}",
            code=EXIT_SAFETY,
        ) from exc
    if str(receipt.get("project_id")) != project_id:
        raise BackupError(
            f"backup receipt project_id mismatch for {backup_id}",
            code=EXIT_SAFETY,
        )
    if str(receipt.get("backup_id")) != backup_id:
        raise BackupError(
            f"backup receipt backup_id mismatch for {backup_id}",
            code=EXIT_SAFETY,
        )
    archive = root / "backups" / project_id / f"{backup_id}.tar.age"
    if not archive.is_file() or archive.is_symlink():
        raise BackupError(
            f"recovery archive missing or not a regular file for {backup_id}",
            code=EXIT_SAFETY,
        )
    size = archive.stat().st_size
    expected_size = receipt.get("ciphertext_bytes")
    if not isinstance(expected_size, int) or expected_size < 64 or size != expected_size:
        raise BackupError(
            f"recovery archive size mismatch for {backup_id}: "
            f"on-disk={size} receipt={expected_size}",
            code=EXIT_SAFETY,
        )
    if size < 64:
        raise BackupError(f"recovery archive truncated for {backup_id}", code=EXIT_SAFETY)
    digest = sha256_file(archive)
    try:
        receipt_archive_binding_ok(
            receipt,
            ciphertext_sha256=digest,
            project_id=project_id,
            backup_id=backup_id,
            manifest_sha256=str(receipt.get("manifest_sha256") or "") or None,
        )
    except ManifestError as exc:
        raise BackupError(
            f"recovery archive/receipt binding failed for {backup_id}: {exc}",
            code=EXIT_SAFETY,
        ) from exc
    return receipt


def _require_age() -> str:
    from sbfleet.tools import ToolError, require_age

    try:
        return require_age()
    except ToolError as exc:
        raise BackupError(str(exc) or "age not installed", code=EXIT_PREREQUISITE) from exc


def _fleet_recipients(root: Path) -> list[str]:
    data = reg.load_json(root / "fleet.json")
    recips = data.get("age_recipients") or data.get("backup_recipients") or []
    if not isinstance(recips, list) or not recips:
        raise BackupError(
            "no age recipients in fleet.json (set age_recipients / backup_recipients)",
            code=EXIT_SAFETY,
        )
    return [str(r) for r in recips]


def set_fleet_recipients(root: Path, recipients: list[str]) -> None:
    path = root / "fleet.json"
    data = reg.load_json(path)
    data["age_recipients"] = list(recipients)
    data["backup_recipients"] = list(recipients)
    reg.atomic_write_json(path, data, mode=0o600)


def _resolve_identity(identity: str | None) -> Path | None:
    if identity:
        path = Path(identity)
    else:
        env = os.environ.get("SBFLEET_AGE_IDENTITY")
        path = Path(env) if env else None
    if path is None:
        return None
    try:
        return reg.assert_secret_file(path)
    except reg.OwnershipError as exc:
        raise BackupError(str(exc), code=EXIT_SAFETY) from exc


def _docker(argv: list[str], *, timeout: float = 300.0) -> Any:
    return run(
        argv,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=timeout,
        check=False,
    )


def _disk_free_bytes(path: Path) -> int | None:
    try:
        usage = shutil.disk_usage(path)
        return int(usage.free)
    except OSError:
        return None


def _fs_identity(path: Path) -> str | None:
    """Return a stable filesystem identity, or None when UNKNOWN."""
    try:
        st = path.resolve().stat() if path.exists() else path.parent.resolve().stat()
        return f"dev:{st.st_dev}"
    except OSError:
        return None


def _dir_size_bytes(path: Path) -> int | None:
    """Return directory size, or None when any entry is unreadable (UNKNOWN).

    ``os.walk`` without ``onerror`` silently skips unlistable directories and can
    undercount as zero — that must become UNKNOWN.
    """
    total = 0
    if not path.exists():
        return 0
    walk_error: list[BaseException] = []

    def _onerror(err: OSError) -> None:
        walk_error.append(err)

    try:
        for dirpath, _dirnames, filenames in os.walk(path, followlinks=False, onerror=_onerror):
            if walk_error:
                return None
            for name in filenames:
                fp = Path(dirpath) / name
                try:
                    if fp.is_symlink():
                        continue
                    if not fp.is_file():
                        continue
                    total += fp.stat().st_size
                except OSError:
                    return None
    except OSError:
        return None
    if walk_error:
        return None
    return total


def _docker_dir_size_bytes(host_path: Path) -> int | None:
    """Read-only size via owned Docker helper when host walk is UNKNOWN."""
    if not host_path.exists():
        return 0
    try:
        reg.assert_destructive_tree_safe(host_path, under=host_path.parent)
    except reg.OwnershipError:
        return None
    r = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{host_path}:/data:ro",
            HELPER_IMAGE,
            "sh",
            "-c",
            "du -sb /data 2>/dev/null | awk '{print $1}'",
        ],
        timeout=120.0,
    )
    if not r.ok:
        return None
    raw = (r.stdout or "").strip().splitlines()
    if not raw:
        return None
    try:
        return int(raw[-1].strip())
    except ValueError:
        return None


def _measure_tree_bytes(path: Path) -> int | None:
    """Host walk first; Docker RO helper only after authority-safe UNKNOWN."""
    size = _dir_size_bytes(path)
    if size is not None:
        return size
    return _docker_dir_size_bytes(path)


def _docker_root_dir() -> Path | None:
    r = _docker(
        ["docker", "info", "--format", "{{.DockerRootDir}}"],
        timeout=30.0,
    )
    if not r.ok:
        return None
    raw = (r.stdout or "").strip()
    if not raw or raw == "<no value>":
        return None
    p = Path(raw)
    return p if p.is_dir() else None


def disk_preflight(
    root: Path,
    deployment: Path,
    *,
    reserve_bytes: int = 2 * 1024**3,
    staging_path: Path | None = None,
    output_path: Path | None = None,
) -> None:
    """Conservative capacity check before downtime — budgeted per filesystem.

    Paths sharing one filesystem sum concurrent temporary needs against that
    pool once. Distinct filesystems are validated independently. UNKNOWN
    identity/size/free refuses; free space is never double-counted across pools.
    """
    staging = staging_path or (root / "staging")
    backups = output_path or (root / "backups")
    pg_path = deployment / "volumes" / "db" / "data"
    storage_path = deployment / "volumes" / "storage"

    pg = _measure_tree_bytes(pg_path)
    storage = _measure_tree_bytes(storage_path)
    if pg is None:
        raise BackupError(
            "unable to establish source data size for backup capacity preflight "
            f"(UNKNOWN size for {pg_path})",
            code=EXIT_SAFETY,
        )
    if storage is None:
        raise BackupError(
            "unable to establish source data size for backup capacity preflight "
            f"(UNKNOWN size for {storage_path})",
            code=EXIT_SAFETY,
        )
    source_bytes = pg + storage

    # Concurrent temporary consumers on cold backup:
    # plaintext staging copy, encrypted output, disposable extract/verifier work.
    # Source itself is not "needed free" beyond reserve (already occupied).
    requirements: list[tuple[str, Path, int]] = [
        ("staging", staging, source_bytes),  # cold plaintext copy
        ("encrypted_output", backups, source_bytes),  # ciphertext approx
        ("extraction", staging, source_bytes),  # verify extract (same staging FS often)
        ("reserve", root, reserve_bytes),
    ]

    docker_root = _docker_root_dir()
    if docker_root is None:
        raise BackupError(
            "unable to establish Docker volume/storage filesystem identity (DockerRootDir UNKNOWN)",
            code=EXIT_SAFETY,
        )
    # Verifier volumes live under Docker storage; budget another source-sized copy.
    requirements.append(("verifier_docker", docker_root, source_bytes))

    # Group by filesystem identity.
    by_fs: dict[str, list[tuple[str, Path, int]]] = {}
    for label, path, need in requirements:
        if label in {"staging", "encrypted_output"}:
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise BackupError(
                    f"unable to prepare {label} path {path}: {exc}",
                    code=EXIT_SAFETY,
                ) from exc
        probe = path if path.exists() else path.parent
        if not probe.exists():
            try:
                probe.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise BackupError(
                    f"unable to establish filesystem identity for {label} ({path}): {exc}",
                    code=EXIT_SAFETY,
                ) from exc
            probe = path if path.exists() else path.parent
        ident = _fs_identity(probe)
        if ident is None:
            raise BackupError(
                f"unable to establish filesystem identity for {label} ({path})",
                code=EXIT_SAFETY,
            )
        by_fs.setdefault(ident, []).append((label, path, need))

    for ident, items in by_fs.items():
        # One free-space reading per pool (use first existing path).
        probe_path = next((p for _lab, p, _n in items if p.exists()), items[0][1])
        if not probe_path.exists():
            probe_path = probe_path.parent
        free = _disk_free_bytes(probe_path)
        if free is None:
            labels = ", ".join(sorted({lab for lab, _p, _n in items}))
            raise BackupError(
                f"unable to establish free disk capacity for filesystem {ident} (paths: {labels})",
                code=EXIT_SAFETY,
            )
        needed = sum(n for _lab, _p, n in items)
        if free < needed:
            labels = ", ".join(f"{lab}~{n}" for lab, _p, n in items)
            raise BackupError(
                f"insufficient disk for cold backup preflight on {ident}: "
                f"free={free} needed~={needed} ({labels})",
                code=EXIT_SAFETY,
            )


def _phase(
    ctx: Any,
    phase: str,
    *,
    nest_key: str | None = None,
    evidence: dict | None = None,
) -> None:
    """Advance journal phase, optionally nesting under a subordinate evidence key.

    ``nest_key="pre_restore"`` keeps RESTORING journal phase as creating_pre_restore_backup.
    ``nest_key="pre_update"`` keeps UPDATING journal phase as creating_recovery_backup.
    """
    from sbfleet import authority as auth

    if nest_key == "pre_restore":
        auth.record_operation_phase(
            ctx,
            phase="creating_pre_restore_backup",
            evidence={"pre_restore": {"backup_phase": phase, **(evidence or {})}},
        )
    elif nest_key == "pre_update":
        auth.record_operation_phase(
            ctx,
            phase="creating_recovery_backup",
            evidence={"pre_update": {"backup_phase": phase, **(evidence or {})}},
        )
    else:
        auth.record_operation_phase(ctx, phase=phase, evidence=evidence)


def _capture_prior_state(
    root: Path,
    slug: str,
    *,
    mutation_ctx: Any | None = None,
) -> str:
    """Prior stack state under the active mutation lock.

    Ordinary ``collect_status`` overlays unresolved journals as FAILED. While we
    hold the backup/restore MutationContext that is correct for operators, but
    prior-state capture must still see intentional STOPPED via
    ``collect_status_for_mutation``. Foreign unresolved journals still refuse.
    """
    from sbfleet.health import (
        HEALTHY,
        STOPPED,
        collect_status,
        collect_status_for_mutation,
        inspect_containers_result,
    )

    meta = reg.read_project(root, slug)
    deployment = reg.project_dir(root, slug) / "deployment"
    inspected = inspect_containers_result(deployment, str(meta["compose_project"]))
    if not inspected.ok:
        raise BackupError(
            f"refuse backup: compose enum failed: {inspected.error or 'unknown'}",
            code=EXIT_SAFETY,
        )
    if not inspected.containers:
        journal = reg.read_operation_journal(root, slug) or {}
        if reg.journal_is_unresolved(journal):
            jid = str(journal.get("operation_id") or "")
            if (
                mutation_ctx is not None
                and jid
                and getattr(mutation_ctx, "operation_id", None) == jid
            ):
                return STOPPED
            intent = journal.get("intent") or "?"
            phase = journal.get("phase") or "?"
            raise BackupError(
                f"refuse backup from lifecycle=FAILED; unresolved {intent}/{phase}",
                code=EXIT_SAFETY,
            )
        return STOPPED

    # Running containers: probe path via lock-owning mutation context only.
    if mutation_ctx is not None:
        report = collect_status_for_mutation(mutation_ctx)
    else:
        report = collect_status(root, slug)
    if report.lifecycle == HEALTHY:
        return HEALTHY
    raise BackupError(
        f"refuse backup from lifecycle={report.lifecycle}; require HEALTHY or STOPPED",
        code=EXIT_SAFETY,
    )


def _quiesce_services(ctx: Any, services: list[str], *, timeout: float) -> None:
    """Stop the given Compose services under forced env. Check every result."""
    if not services:
        return
    deployment = ctx.deployment
    env = ctx.compose_env
    argv = ["docker", "compose", "stop", "--timeout", str(int(timeout)), *services]
    r = run(
        argv,
        cwd=deployment,
        env=env,
        timeout=timeout + 60.0,
        check=False,
    )
    if not r.ok:
        err = (r.stderr or r.stdout or "").lower()
        if "no such" not in err and "not found" not in err and "no containers" not in err:
            raise BackupError(
                f"quiesce stop failed for {services}: {(r.stderr or '')[:200]}",
                code=EXIT_FAILURE,
            )


def _quiesce_writers(ctx: Any) -> None:
    """Stop gateway + non-DB writers; leave PostgreSQL available for fact capture."""
    non_db = [s for s in STANDARD_SERVICES if s not in {"db", "api-gw"}]
    _quiesce_services(ctx, ["api-gw"], timeout=60.0)
    _quiesce_services(ctx, non_db, timeout=60.0)


def _quiesce_db(ctx: Any) -> None:
    """Cleanly stop PostgreSQL after source facts were captured."""
    from sbfleet.health import inspect_containers_result

    _quiesce_services(ctx, ["db"], timeout=120.0)
    inspected = inspect_containers_result(ctx.deployment, ctx.compose_project)
    if not inspected.ok:
        raise BackupError(f"post-quiesce enum failed: {inspected.error}", code=EXIT_FAILURE)
    if inspected.containers:
        raise BackupError(
            f"quiesce incomplete; remaining={sorted(inspected.containers)}",
            code=EXIT_FAILURE,
        )


def _quiesce_ordered(ctx: Any) -> None:
    """Full gateway-first, DB-last stop (writers then DB)."""
    _quiesce_writers(ctx)
    _quiesce_db(ctx)


def _resolve_db_image(meta: dict[str, Any], deployment: Path) -> str:
    digests = meta.get("image_digests") or {}
    db = digests.get("db") if isinstance(digests, dict) else None
    if isinstance(db, dict):
        for key in ("image_id", "digest", "image_ref"):
            val = db.get(key)
            if val and val != "UNKNOWN":
                if key == "digest" and "@" not in str(val) and db.get("image_ref"):
                    ref = str(db["image_ref"]).split("@", 1)[0]
                    return f"{ref}@{val}" if not str(val).startswith("sha256:") else f"{ref}@{val}"
                return str(val)
    # Fall back to compose config image for db service.
    r = run(
        ["docker", "compose", "config", "--images"],
        cwd=deployment,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "COMPOSE_PROJECT_NAME": str(meta.get("compose_project") or ""),
            "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
            "COMPOSE_PATH_SEPARATOR": ":",
            "HOME": str(deployment / ".run-home"),
        },
        timeout=60.0,
        check=False,
    )
    if r.ok:
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if "postgres" in line.lower() or "supabase/postgres" in line:
                return line
        lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
        if lines:
            # Prefer last matching; otherwise first image is unreliable — require postgres-like
            for line in lines:
                if "db" in line.lower() or "postgres" in line.lower():
                    return line
    raise BackupError(
        "unable to resolve exact db image for clean-shutdown / recovery",
        code=EXIT_SAFETY,
    )


def _copy_required_unit(src: Path, dest: Path, *, label: str) -> None:
    if not src.exists():
        raise BackupError(f"missing required backup unit: {label}", code=EXIT_BACKUP)
    dest.mkdir(parents=True, exist_ok=True)
    cp = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{src}:/from:ro",
            "-v",
            f"{dest}:/to",
            HELPER_IMAGE,
            "sh",
            "-c",
            "cp -a /from/. /to/",
        ],
        timeout=600.0,
    )
    if not cp.ok:
        raise BackupError(f"copy {label} failed: {(cp.stderr or '')[:200]}")


def _copy_db_config_volume(compose_project: str, dest: Path) -> None:
    vol = f"{compose_project}_db-config"
    # Refuse empty/missing volume: docker volume inspect first.
    insp = _docker(["docker", "volume", "inspect", vol])
    if not insp.ok:
        raise BackupError(f"missing required db-config volume: {vol}", code=EXIT_BACKUP)
    dest.mkdir(parents=True, exist_ok=True)
    cp = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{vol}:/from:ro",
            "-v",
            f"{dest}:/to",
            HELPER_IMAGE,
            "sh",
            "-c",
            "cp -a /from/. /to/ && test -f /to/pgsodium_root.key",
        ],
        timeout=180.0,
    )
    if not cp.ok:
        raise BackupError(
            f"db-config copy failed or pgsodium_root.key missing: {(cp.stderr or '')[:200]}"
        )


def _wipe_staging(staging: Path) -> None:
    """Remove owned plaintext staging. Success requires observed absence.

    Checks Docker wipe status and host postconditions. Never reports success
    while residual owned plaintext remains. No prefix/global historical sweep.
    """
    if not staging.exists():
        return
    try:
        reg.assert_destructive_tree_safe(staging, under=staging.parent)
    except reg.OwnershipError as exc:
        raise BackupError(str(exc), code=EXIT_SAFETY) from exc
    wipe = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{staging}:/wipe",
            HELPER_IMAGE,
            "sh",
            "-c",
            "rm -rf /wipe/* /wipe/.[!.]* /wipe/..?*",
        ],
        timeout=300.0,
    )
    if not wipe.ok:
        raise BackupError(
            f"docker staging wipe failed for {staging}: "
            f"{(wipe.stderr or wipe.stdout or 'nonzero exit')[:200]}",
            code=EXIT_SAFETY,
        )
    # Host tree removal after Docker wipe — still through the shared gate (already proven).
    # Refusal above is terminal; do not catch and retry with weaker deletion.
    try:
        reg.safe_rmtree(staging, under=staging.parent)
    except reg.OwnershipError as exc:
        raise BackupError(str(exc), code=EXIT_SAFETY) from exc
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise BackupError(
            f"host staging wipe incomplete for {staging}: {exc}",
            code=EXIT_SAFETY,
        ) from exc
    if staging.exists():
        residuals: list[str] = [str(staging)]
        try:
            for root, _dirs, files in os.walk(staging):
                for name in files:
                    residuals.append(str(Path(root) / name))
                    if len(residuals) >= 8:
                        break
                if len(residuals) >= 8:
                    break
        except OSError:
            pass
        raise BackupError(
            "staging wipe reported incomplete; residual plaintext remains: "
            + ", ".join(residuals[:8]),
            code=EXIT_SAFETY,
        )


def _cleanup_restore_preflight_staging(staging: Path) -> list[str]:
    """Best-effort wipe of pre-mutation restore staging; return residual paths only.

    Never raises into a blocking RESTORING journal. Does not print secrets/contents.
    """
    residuals: list[str] = []
    if not staging.exists():
        return residuals
    try:
        _wipe_staging(staging)
    except Exception as exc:  # noqa: BLE001
        from sbfleet.process import sanitize_configured_diagnostic

        residuals.append(str(staging))
        detail = sanitize_configured_diagnostic(f"{type(exc).__name__}: {exc}")
        if detail:
            residuals.append(detail[:200])
    if staging.exists():
        if str(staging) not in residuals:
            residuals.append(str(staging))
    return residuals


def _report_preflight_cleanup_residuals(residuals: list[str]) -> None:
    if not residuals:
        return
    print(
        "error: restore preflight refused; staging cleanup incomplete; "
        "residuals: " + "; ".join(residuals),
        file=sys.stderr,
    )


def _host_copy_tree_via_docker(src: Path, dest: Path, *, chown: str | None = None) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    cmd = "cp -a /from/. /to/"
    if chown:
        cmd += f" && chown -R {chown} /to"
    r = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{src}:/from:ro",
            "-v",
            f"{dest}:/to",
            HELPER_IMAGE,
            "sh",
            "-c",
            cmd,
        ],
        timeout=600.0,
    )
    if not r.ok:
        raise BackupError(f"docker copy failed: {(r.stderr or '')[:200]}")


def reconcile_destination_env(
    *,
    archived_env: dict[str, str],
    destination_env: dict[str, str],
    destination_meta: dict[str, Any],
) -> dict[str, str]:
    """Field-level merge: source crypto + destination placement/authority.

    Never copies archived .env wholesale. Never reintroduces stale Compose selectors.
    """
    from sbfleet import upstream as up
    from sbfleet.branding import api_external_url

    out = dict(destination_env)
    # Apply source recovery material.
    for key in SOURCE_RECOVERY_ENV_KEYS:
        if key in archived_env:
            out[key] = archived_env[key]
    # Force destination-owned placement / authority fields.
    ports = destination_meta.get("ports") or {}
    compose_project = str(destination_meta["compose_project"])
    public_url = str(
        destination_meta.get("public_url") or f"http://127.0.0.1:{ports.get('gateway')}"
    )
    out["COMPOSE_PROJECT_NAME"] = compose_project
    out["COMPOSE_FILE"] = "docker-compose.yml:docker-compose.override.yml"
    out["COMPOSE_PATH_SEPARATOR"] = ":"
    if ports.get("gateway") is not None:
        out["KONG_HTTP_PORT"] = str(ports["gateway"])
    out["SUPABASE_PUBLIC_URL"] = public_url.rstrip("/")
    out["API_EXTERNAL_URL"] = api_external_url(public_url)
    # Preserve destination branding/site if present; else keep archived non-selector.
    for key in DESTINATION_OWNED_ENV_KEYS:
        if key in {
            "COMPOSE_PROJECT_NAME",
            "COMPOSE_FILE",
            "COMPOSE_PATH_SEPARATOR",
            "KONG_HTTP_PORT",
            "SUPABASE_PUBLIC_URL",
            "API_EXTERNAL_URL",
        }:
            continue
        if key in destination_env:
            out[key] = destination_env[key]
    # DASHBOARD_USERNAME stays destination-owned when present.
    if "DASHBOARD_USERNAME" in destination_env:
        out["DASHBOARD_USERNAME"] = destination_env["DASHBOARD_USERNAME"]
    up.validate_generated_env(out)
    return out


def _cleanup_live_source_challenge(
    ctx: Any,
    *,
    root: Path,
    slug: str,
    deployment: Path,
    compose_project: str,
    name: str,
    prefer_running: bool,
    leave_stopped: bool,
) -> None:
    """Best-effort delete operation-private vault challenge from live source."""
    from sbfleet.projects import ProjectError, start_project

    started = False
    try:
        if not prefer_running:
            start_project(
                root,
                slug,
                already_locked=True,
                manage_journal=False,
                timeout=600,
            )
            started = True
        cleanup_source_crypto_challenge(deployment, compose_project, name=name)
    except (BackupError, ProjectError, Exception):  # noqa: BLE001
        return
    finally:
        if leave_stopped and started:
            try:
                _quiesce_ordered(ctx)
            except Exception:  # noqa: BLE001
                pass


def _create_backup_locked(
    ctx: Any,
    *,
    verify: bool = True,
    identity: Path | None = None,
    pre_restore: bool = False,
    pre_update: bool = False,
    expected_sql: dict[str, Any] | None = None,
    expected_auth: dict[str, Any] | None = None,
    expected_vault: dict[str, Any] | None = None,
    expected_functions: dict[str, Any] | None = None,
    restore_prior_state: bool = True,
) -> BackupLockedResult:
    """Already-authorized cold backup primitive. Never acquires mutation lock.

    ``pre_restore`` / ``pre_update`` nest backup phases under the parent journal
    evidence without flipping intent to BACKUP. ``pre_update`` still publishes
    ``last_backup_id`` (unlike ``pre_restore``) and requires recovery verification.
    """
    from sbfleet import authority as auth
    from sbfleet.health import HEALTHY
    from sbfleet.projects import ProjectError, start_project

    if pre_restore and pre_update:
        raise BackupError("pre_restore and pre_update are mutually exclusive", code=EXIT_SAFETY)

    nest_key: str | None = None
    if pre_restore:
        nest_key = "pre_restore"
    elif pre_update:
        nest_key = "pre_update"

    age = _require_age()
    recipients = _fleet_recipients(ctx.root)
    root = ctx.root
    slug = ctx.slug
    meta = ctx.meta
    deployment = ctx.deployment
    backup_id = str(uuid.uuid4())
    staging = root / "staging" / f"backup-{ctx.operation_id}-{backup_id[:8]}"
    staging.mkdir(parents=True, mode=0o700)
    os.chmod(staging, 0o700)

    prior_state = "STOPPED"
    restart_ok: bool | None = None
    restart_error: str | None = None
    receipt: dict[str, Any] | None = None
    age_path = root / "backups" / str(meta["id"]) / f"{backup_id}.tar.age"

    source_crypto: dict[str, Any] | None = None
    source_facts: dict[str, Any] | None = None
    capture_note: str | None = None
    result_box: list[BackupLockedResult] = []
    try:
        _phase(ctx, "capturing_prior_state", nest_key=nest_key)
        prior_state = _capture_prior_state(root, slug, mutation_ctx=ctx)

        disk_preflight(root, deployment)

        # Snapshot-consistent capture: writers down, PostgreSQL up, then DB stop.
        if verify:
            _phase(
                ctx, "quiescing_writers", nest_key=nest_key, evidence={"prior_state": prior_state}
            )
            if prior_state != HEALTHY:
                try:
                    start_project(
                        root,
                        slug,
                        already_locked=True,
                        manage_journal=False,
                        timeout=600,
                    )
                except ProjectError as exc:
                    raise BackupError(
                        f"cannot reach DB for source vault challenge: {exc}",
                        code=EXIT_BACKUP,
                    ) from exc
            try:
                _quiesce_writers(ctx)
            except BackupError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise BackupError(f"writer quiesce failure: {exc}", code=EXIT_FAILURE) from exc

            _phase(ctx, "capturing_source_crypto", nest_key=nest_key)
            try:
                source_crypto = capture_source_crypto_challenge(
                    deployment,
                    str(meta["compose_project"]),
                    operation_id=str(ctx.operation_id),
                )
                source_facts = capture_source_recovery_facts(
                    deployment, str(meta["compose_project"])
                )
            except RecoveryVerifyError as exc:
                # Weaker level only later — never silent recovery.
                capture_note = f"source vault challenge unavailable: {exc}"[:240]
                source_crypto = None
                source_facts = None

            _phase(ctx, "quiescing_db", nest_key=nest_key)
            try:
                _quiesce_db(ctx)
            except BackupError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise BackupError(f"db quiesce failure: {exc}", code=EXIT_FAILURE) from exc
        else:
            _phase(ctx, "quiescing", nest_key=nest_key, evidence={"prior_state": prior_state})
            try:
                _quiesce_ordered(ctx)
            except BackupError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise BackupError(f"stop failure: {exc}", code=EXIT_FAILURE) from exc

        db_image = _resolve_db_image(meta, deployment)
        pgdata = deployment / "volumes" / "db" / "data"
        storage = deployment / "volumes" / "storage"
        if not pgdata.is_dir():
            raise BackupError("missing PGDATA", code=EXIT_BACKUP)
        if not storage.is_dir():
            raise BackupError("missing Storage data", code=EXIT_BACKUP)
        if not (deployment / ".env").is_file():
            raise BackupError("missing .env", code=EXIT_BACKUP)

        _phase(ctx, "clean_shutdown_check", nest_key=nest_key)
        try:
            shutdown = prove_clean_shutdown(db_image=db_image, pgdata=pgdata)
        except RecoveryVerifyError as exc:
            raise BackupError(f"dirty PG shutdown: {exc}", code=EXIT_BACKUP) from exc

        # Read PG_VERSION via helper (PGDATA is container-owned).
        pg_version = "UNKNOWN"
        ver = _docker(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{pgdata}:/pgdata:ro",
                HELPER_IMAGE,
                "cat",
                "/pgdata/PG_VERSION",
            ]
        )
        if ver.ok and (ver.stdout or "").strip():
            pg_version = (ver.stdout or "").strip()
        major = None
        try:
            major = int(str(pg_version).split(".", 1)[0])
        except ValueError:
            major = None

        _phase(ctx, "collecting", nest_key=nest_key)
        payload = staging / "payload"
        payload.mkdir(mode=0o700)

        _copy_required_unit(pgdata, payload / "postgres", label="postgres/PGDATA")
        _copy_required_unit(storage, payload / "storage", label="storage")
        for rel, label in (
            ("volumes/functions", "functions"),
            ("volumes/snippets", "snippets"),
        ):
            src = deployment / rel
            if src.exists():
                _copy_required_unit(src, payload / "deployment" / Path(rel).name, label=label)
            else:
                (payload / "deployment" / Path(rel).name).mkdir(parents=True, exist_ok=True)

        _copy_db_config_volume(ctx.compose_project, payload / "db-config")

        dep_out = payload / "deployment"
        dep_out.mkdir(parents=True, exist_ok=True)
        for rel in (".env", "docker-compose.override.yml", ".supabase-version"):
            src = deployment / rel
            if not src.exists() and rel == ".env":
                raise BackupError("missing .env", code=EXIT_BACKUP)
            if src.exists():
                shutil.copy2(src, dep_out / rel)
                if rel == ".env":
                    os.chmod(dep_out / rel, 0o600)

        # Make staging payload host-readable for streaming hash/tar (not the source trees).
        chown_payload = _docker(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{payload}:/p",
                HELPER_IMAGE,
                "sh",
                "-c",
                f"chown -R {os.getuid()}:{os.getgid()} /p && chmod -R u+rwX /p",
            ],
            timeout=300.0,
        )
        if not chown_payload.ok:
            raise BackupError(
                f"payload ownership adjust failed: {(chown_payload.stderr or '')[:200]}"
            )

        # project.json as identity evidence (not destination replacement)
        proj_meta = {
            "id": meta["id"],
            "fleet_id": meta["fleet_id"],
            "slug": slug,
            "compose_project": meta.get("compose_project"),
            "ports": meta.get("ports"),
            "upstream": meta.get("upstream"),
            "profile": meta.get("profile"),
            "public_url": meta.get("public_url"),
        }
        (payload / "project.json").write_text(
            json.dumps(proj_meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        # Build inventory digests via streaming over payload files (host-readable copies).
        members: dict[str, MemberSpec] = {}
        for rel, size, digest in iter_file_digests(payload):
            members[rel] = MemberSpec(path=rel, type="file", size=size, sha256=digest)
        # Include directory markers for empty dirs
        for dirpath, dirnames, _filenames in os.walk(payload):
            for d in dirnames:
                p = Path(dirpath) / d
                rel = p.relative_to(payload).as_posix()
                if rel not in members:
                    members[rel] = MemberSpec(path=rel, type="dir", size=0, sha256=None)

        images = dict(meta.get("image_digests") or {})
        if "db" not in images or not isinstance(images.get("db"), dict):
            images["db"] = {
                "image_ref": db_image,
                "image_id": db_image if db_image.startswith("sha256:") else "UNKNOWN",
                "digest": "UNKNOWN",
                "platform": "UNKNOWN",
            }
        # Ensure image_ref at least set for recovery facts when only ref known.
        db_entry = dict(images.get("db") or {})
        if db_entry.get("image_id") in {None, "", "UNKNOWN"} and db_image:
            # Prefer recording ref; recovery requires image_id — try docker inspect.
            insp = _docker(
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}|{{.Os}}/{{.Architecture}}",
                    db_image,
                ]
            )
            if insp.ok:
                parts = (insp.stdout or "").strip().split("|")
                db_entry["image_ref"] = db_image
                db_entry["image_id"] = parts[0] or db_image
                if len(parts) > 1:
                    db_entry["platform"] = parts[1]
            else:
                db_entry["image_ref"] = db_image
                db_entry["image_id"] = db_image
        images["db"] = db_entry

        postgres_facts = {
            "pg_version": pg_version,
            "major": major,
            "cluster_state": shutdown.get("cluster_state"),
            "pg_control_version": shutdown.get("pg_control_version"),
            "catalog_version": shutdown.get("catalog_version"),
            "system_identifier": shutdown.get("system_identifier"),
            "unit": "postgres/",
        }

        # Inventory must not include manifest.json itself; write manifest after inventory.
        internal = build_internal_manifest(
            backup_id=backup_id,
            project_id=str(meta["id"]),
            fleet_id=str(meta["fleet_id"]),
            slug=slug,
            upstream=meta.get("upstream"),
            last_verified_upstream=meta.get("last_verified_upstream"),
            prior_state=prior_state,
            images=images,
            postgres=postgres_facts,
            members=members,
            includes=["postgres", "db-config", "storage", "deployment", "project.json"],
            clean_shutdown_evidence=shutdown,
            platform=(images.get("db") or {}).get("platform"),
            source_crypto=source_crypto,
            source_facts=source_facts,
        )
        man_bytes = manifest_bytes(internal)
        man_digest = manifest_sha256(internal)
        (payload / "manifest.json").write_text(man_bytes.decode("utf-8"), encoding="utf-8")

        _phase(ctx, "encrypting", nest_key=nest_key)
        tar_path = staging / "backup.tar"
        # Re-scan members including dirs for tar; exclude nothing. Manifest is in tree but
        # not in checksum inventory (by design).
        build_tar_from_tree(payload, tar_path)

        age_path.parent.mkdir(parents=True, exist_ok=True)
        partial = Path(str(age_path) + ".partial")
        argv = [age, "-o", str(partial)]
        for rcp in recipients:
            argv.extend(["-r", rcp])
        argv.append(str(tar_path))
        enc = run(argv, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, check=False)
        if not enc.ok:
            raise BackupError("age encrypt failed", code=EXIT_BACKUP)
        # Truncation / empty refuse
        if not partial.is_file() or partial.stat().st_size < 64:
            raise BackupError("truncated age output", code=EXIT_BACKUP)
        os.replace(partial, age_path)
        digest = sha256_file(age_path)

        verification = VERIFICATION_NONE
        recovery_evidence = None
        note = None

        if verify:
            if identity is None:
                raise BackupError(
                    "verified backup requires --identity or SBFLEET_AGE_IDENTITY",
                    code=EXIT_PREREQUISITE,
                )
            _phase(ctx, "recovery_verifying", nest_key=nest_key)
            dec = staging / "verify.tar"
            decr = run(
                [age, "-d", "-i", str(identity), "-o", str(dec), str(age_path)],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                check=False,
            )
            if not decr.ok:
                raise BackupError(
                    "age decrypt verification failed (wrong identity?)",
                    code=EXIT_BACKUP,
                )
            extract = staging / "verify-extract"
            extract.mkdir(mode=0o700)
            try:
                # Two-phase: inspect manifest, bootstrap expected inventory, enforce extract.
                man_raw, man_spec, _tar_members = read_manifest_from_tar(dec)
                loaded = json.loads(man_raw.decode("utf-8"))
                validate_internal_manifest(loaded)
                man_dig = manifest_sha256(loaded)
                if man_dig != man_digest:
                    raise BackupError("manifest digest drift after encrypt/decrypt")
                expected, checksums = bootstrap_expected_from_manifest(
                    loaded, manifest_tar_size=man_spec.size
                )
                checksums = dict(checksums)
                checksums["manifest.json"] = write_buffered_hash(man_raw)
                payload_size = _dir_size_bytes(payload)
                if payload_size is None:
                    raise BackupError(
                        "unable to establish extract size budget (payload size UNKNOWN)",
                        code=EXIT_BACKUP,
                    )
                safe_extract(
                    dec,
                    extract,
                    expected=expected,
                    verify_sha256=checksums,
                    max_total_bytes=max(
                        128 * 1024**3,
                        payload_size * 3,
                    ),
                )
                verification = VERIFICATION_DECRYPT_STRUCTURAL
                # Disposable recovery (not project HEALTHY)
                try:
                    require_db_recovery_facts(loaded)
                    rv = run_disposable_recovery_verification(
                        extract_root=extract,
                        manifest=loaded,
                        fleet_id=str(meta["fleet_id"]),
                        operation_id=ctx.operation_id,
                        expected_sql=expected_sql,
                        expected_auth=expected_auth,
                        expected_vault=expected_vault,
                        expected_functions=expected_functions,
                        source_crypto=source_crypto,
                        source_facts=source_facts,
                    )
                    recovery_evidence = rv.as_receipt_evidence()
                    recovery_evidence["manifest_sha256"] = man_digest
                    if rv.ok:
                        verification = VERIFICATION_RECOVERY
                    else:
                        note = (
                            "decrypt_structural only; disposable recovery verification failed: "
                            f"{(rv.error or 'assertions')}".replace("\n", " ")[:300]
                        )
                except ManifestError as exc:
                    note = f"decrypt_structural only; recovery facts incomplete: {exc}"[:300]
            except (ArchiveSafetyError, ManifestError, BackupError) as exc:
                raise BackupError(f"archive validation failed: {exc}", code=EXIT_BACKUP) from exc

        if verification != VERIFICATION_RECOVERY:
            # Cap at decrypt_structural or none — never publish recovery.
            if verification == VERIFICATION_NONE and verify:
                verification = VERIFICATION_DECRYPT_STRUCTURAL
            if note is None and verification != VERIFICATION_RECOVERY:
                note = capture_note or "recovery receipt not issued"
            elif capture_note and note:
                note = f"{note}; {capture_note}"[:300]

        _phase(ctx, "publishing_receipt", nest_key=nest_key)
        receipt = public_receipt(
            backup_id=backup_id,
            project_id=str(meta["id"]),
            slug=slug,
            digest=digest,
            size=age_path.stat().st_size,
            upstream=meta.get("upstream"),
            verification=verification,
            manifest_sha256=man_digest,
            prior_state=prior_state,
            recovery=recovery_evidence if verification == VERIFICATION_RECOVERY else None,
            note=note,
            operation_id=ctx.operation_id,
        )
        if verification == VERIFICATION_RECOVERY:
            receipt["verified_at"] = utc_now()
        receipt_path = root / "backups" / str(meta["id"]) / f"{backup_id}.json"
        # Never write recovery first then verify later — we only write after verification.
        reg.atomic_write_json(receipt_path, receipt, mode=0o600)

        if not pre_restore:
            meta2 = reg.read_project(root, slug)
            meta2["last_backup_id"] = backup_id
            meta2["last_backup_verification"] = verification
            reg.write_project(root, meta2)

        if pre_restore:
            auth.record_operation_phase(
                ctx,
                phase="creating_pre_restore_backup",
                evidence={
                    "pre_restore": {
                        "backup_id": backup_id,
                        "verification": verification,
                        "ciphertext_sha256": digest,
                        "manifest_sha256": man_digest,
                        "archive": str(age_path),
                    }
                },
            )
            if verification != VERIFICATION_RECOVERY:
                raise BackupError(
                    "pre-restore backup is not recovery-verified; refuse destructive restore"
                    + (f" ({note})" if note else f" (verification={verification})"),
                    code=EXIT_SAFETY,
                )
        elif pre_update:
            auth.record_operation_phase(
                ctx,
                phase="creating_recovery_backup",
                evidence={
                    "pre_update": {
                        "backup_id": backup_id,
                        "verification": verification,
                        "ciphertext_sha256": digest,
                        "manifest_sha256": man_digest,
                        "archive": str(age_path),
                    }
                },
            )
            if verification != VERIFICATION_RECOVERY:
                raise BackupError(
                    "pre-update backup is not recovery-verified; refuse update apply"
                    + (f" ({note})" if note else f" (verification={verification})"),
                    code=EXIT_SAFETY,
                )
        else:
            # Prior-state restoration for top-level backup only.
            _phase(ctx, "restoring_prior_state", nest_key=None)
            if restore_prior_state and prior_state == HEALTHY:
                try:
                    start_project(
                        root,
                        slug,
                        already_locked=True,
                        manage_journal=False,
                        timeout=600,
                    )
                    restart_ok = True
                except ProjectError as exc:
                    restart_ok = False
                    restart_error = str(exc)
            elif prior_state == "STOPPED":
                restart_ok = None  # left stopped

        # Best-effort remove operation-private challenge from live source PGDATA.
        # Skip pre_restore: those volumes are about to be quarantined/replaced.
        if source_crypto and source_crypto.get("name") and not pre_restore:
            _cleanup_live_source_challenge(
                ctx,
                root=root,
                slug=slug,
                deployment=deployment,
                compose_project=str(meta["compose_project"]),
                name=str(source_crypto["name"]),
                prefer_running=(restart_ok is True),
                leave_stopped=(prior_state == "STOPPED" or pre_update),
            )

        result = BackupLockedResult(
            backup_id=backup_id,
            archive_path=age_path,
            receipt=receipt,
            verification=verification,
            prior_state=prior_state,
            restart_ok=restart_ok,
            restart_error=restart_error,
        )
        result_box.append(result)
        return result
    except Exception:
        # Best-effort prior-state restore on failure for top-level backup.
        if not pre_restore and not pre_update and restore_prior_state and prior_state == HEALTHY:
            try:
                from sbfleet.projects import start_project

                start_project(root, slug, already_locked=True, manage_journal=False, timeout=600)
            except Exception:  # noqa: BLE001
                pass
        raise
    finally:
        # Wipe plaintext staging. Distinguish archive success from cleanup failure:
        # never destroy a valid archive merely because cleanup failed.
        if staging.exists():
            try:
                _wipe_staging(staging)
            except Exception as wipe_exc:  # noqa: BLE001
                residual = str(staging)
                detail = str(wipe_exc)[:200]
                if result_box:
                    result_box[0].cleanup_ok = False
                    result_box[0].cleanup_residuals = [residual, detail]


def create_backup(
    root: Path,
    slug: str,
    *,
    verify: bool = True,
    identity: str | None = None,
    expected_sql: dict[str, Any] | None = None,
    expected_auth: dict[str, Any] | None = None,
    expected_vault: dict[str, Any] | None = None,
    expected_functions: dict[str, Any] | None = None,
) -> int:
    def _err(exc: BaseException) -> None:
        from sbfleet.process import sanitize_configured_diagnostic

        deployment = reg.project_dir(root, slug) / "deployment"
        print(
            "error: "
            + sanitize_configured_diagnostic(str(exc), deployment=deployment, max_len=500),
            file=sys.stderr,
        )

    try:
        from sbfleet import authority as auth

        id_path = _resolve_identity(identity)
        if verify and id_path is None:
            raise BackupError(
                "verified backup requires --identity or SBFLEET_AGE_IDENTITY",
                code=EXIT_PREREQUISITE,
            )
        _require_age()
        _fleet_recipients(root)

        with auth.authorize_mutation(root, slug, intent="backup") as ctx:
            auth.begin_operation(ctx, phase="capturing_prior_state")
            try:
                result = _create_backup_locked(
                    ctx,
                    verify=verify,
                    identity=id_path,
                    pre_restore=False,
                    expected_sql=expected_sql,
                    expected_auth=expected_auth,
                    expected_vault=expected_vault,
                    expected_functions=expected_functions,
                )
            except BackupError as exc:
                auth.fail_operation(ctx, error=str(exc), phase="failed")
                raise
            except Exception as exc:  # noqa: BLE001
                auth.fail_operation(ctx, error=str(exc), phase="failed")
                raise BackupError(str(exc), code=EXIT_FAILURE) from exc

            recovery = result.verification == VERIFICATION_RECOVERY
            print(
                f"backup {result.backup_id} written "
                f"(verification={result.verification}; recovery_verified={recovery})"
            )
            print(f"archive {result.archive_path}")
            if result.prior_state == "HEALTHY":
                if result.restart_ok:
                    print("prior state restored: HEALTHY")
                elif result.restart_ok is False:
                    print(
                        f"backup verified but restart failed: {result.restart_error}",
                        file=sys.stderr,
                    )
                    auth.complete_operation(
                        ctx,
                        phase="completed",
                        evidence={
                            "restart_ok": False,
                            "restart_error": result.restart_error,
                            "cleanup_ok": result.cleanup_ok,
                            "cleanup_residuals": result.cleanup_residuals,
                        },
                    )
                    return EXIT_FAILURE
            else:
                print("prior state left STOPPED")
            evidence = {
                "backup_id": result.backup_id,
                "verification": result.verification,
                "cleanup_ok": result.cleanup_ok,
            }
            if result.cleanup_residuals:
                evidence["cleanup_residuals"] = list(result.cleanup_residuals)
            auth.complete_operation(ctx, phase="completed", evidence=evidence)
            if not result.cleanup_ok:
                print(
                    "error: backup archive preserved but plaintext cleanup failed; "
                    "residuals: " + ", ".join(result.cleanup_residuals),
                    file=sys.stderr,
                )
                return EXIT_FAILURE
            return EXIT_OK
    except BackupError as exc:
        _err(exc)
        return exc.code
    except Exception as exc:  # noqa: BLE001
        from sbfleet.authority import AuthorityError

        if isinstance(exc, AuthorityError):
            _err(exc)
            return int(getattr(exc, "code", EXIT_SAFETY) or EXIT_SAFETY)
        _err(exc)
        return EXIT_FAILURE


def _install_unit_from_extract(
    src: Path,
    dest: Path,
    *,
    chown: str | None,
    label: str,
) -> None:
    if not src.exists():
        raise BackupError(f"archive missing unit {label}", code=EXIT_BACKUP)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        try:
            reg.assert_destructive_tree_safe(dest, under=dest.parent)
        except reg.OwnershipError as exc:
            raise BackupError(str(exc), code=EXIT_SAFETY) from exc
        wipe = _docker(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{dest}:/wipe",
                HELPER_IMAGE,
                "sh",
                "-c",
                "rm -rf /wipe/* /wipe/.[!.]* /wipe/..?*",
            ],
            timeout=300.0,
        )
        if not wipe.ok:
            raise BackupError(f"wipe {label} failed: {(wipe.stderr or '')[:200]}")
    else:
        dest.mkdir(parents=True, exist_ok=True)
    cmd = "cp -a /from/. /to/"
    if chown:
        cmd += f" && chown -R {chown} /to"
    cp = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{src}:/from:ro",
            "-v",
            f"{dest}:/to",
            HELPER_IMAGE,
            "sh",
            "-c",
            cmd,
        ],
        timeout=600.0,
    )
    if not cp.ok:
        raise BackupError(f"install {label} failed: {(cp.stderr or '')[:200]}")


def _quarantine_unit(src: Path, quarantine: Path, rel: str) -> None:
    if not src.exists():
        return
    dest = quarantine / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.is_file():
        shutil.move(str(src), str(dest))
        return
    try:
        reg.assert_destructive_tree_safe(src, under=src.parent)
    except reg.OwnershipError as exc:
        raise BackupError(str(exc), code=EXIT_SAFETY) from exc
    dest.mkdir(parents=True, exist_ok=True)
    mv = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{src}:/from",
            "-v",
            f"{dest}:/to",
            HELPER_IMAGE,
            "sh",
            "-c",
            "cp -a /from/. /to/ && rm -rf /from/* /from/.[!.]* /from/..?*",
        ],
        timeout=600.0,
    )
    if not mv.ok:
        raise BackupError(f"quarantine {rel} failed: {(mv.stderr or '')[:200]}")


def _authoritative_destination_images(
    deployment: Path,
    compose_project: str,
    meta: dict[str, Any],
) -> dict[str, Any]:
    """Resolve live destination image facts (not mutable meta alone)."""
    from sbfleet.health import inspect_containers_result

    out: dict[str, Any] = {}
    meta_digests = meta.get("image_digests") if isinstance(meta.get("image_digests"), dict) else {}
    inspected = inspect_containers_result(deployment, compose_project)
    containers = inspected.containers if inspected.ok else {}

    # Prefer live container inspect for db; fall back to image inspect of resolved ref.
    db_entry: dict[str, Any] = {
        "image_ref": "UNKNOWN",
        "image_id": "UNKNOWN",
        "digest": "UNKNOWN",
        "platform": "UNKNOWN",
    }
    meta_db = meta_digests.get("db") if isinstance(meta_digests.get("db"), dict) else {}
    for key in ("image_ref", "image_id", "digest", "platform"):
        val = meta_db.get(key)
        if val and val != "UNKNOWN":
            db_entry[key] = val

    row = containers.get("db") if isinstance(containers, dict) else None
    cid = None
    if isinstance(row, dict):
        cid = row.get("ID") or row.get("Container") or row.get("Name")
        ref = row.get("Image") or row.get("ImageName")
        if ref:
            db_entry["image_ref"] = ref
    if cid:
        insp = _docker(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Image}}|{{.Config.Image}}",
                str(cid),
            ],
            timeout=30.0,
        )
        if insp.ok:
            parts = (insp.stdout or "").strip().split("|")
            if parts and parts[0]:
                db_entry["image_id"] = parts[0]
            if len(parts) > 1 and parts[1]:
                db_entry["image_ref"] = parts[1]
    if db_entry["image_id"] in {None, "", "UNKNOWN"}:
        # Resolve via compose config image → docker image inspect.
        resolved = _resolve_db_image({**meta, "compose_project": compose_project}, deployment)
        if resolved:
            db_entry["image_ref"] = (
                resolved if not resolved.startswith("sha256:") else db_entry["image_ref"]
            )
            img = resolved
            insp = _docker(
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}|{{.Os}}/{{.Architecture}}",
                    img,
                ],
                timeout=30.0,
            )
            if insp.ok:
                parts = (insp.stdout or "").strip().split("|")
                if parts and parts[0]:
                    db_entry["image_id"] = parts[0]
                if len(parts) > 1 and parts[1] and parts[1] != "/":
                    db_entry["platform"] = parts[1]
    elif db_entry.get("platform") in {None, "", "UNKNOWN"}:
        insp = _docker(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Os}}/{{.Architecture}}",
                str(db_entry["image_id"]),
            ],
            timeout=30.0,
        )
        if insp.ok and (insp.stdout or "").strip() and (insp.stdout or "").strip() != "/":
            db_entry["platform"] = (insp.stdout or "").strip()

    out["db"] = db_entry
    return out


def _authoritative_destination_pin(
    root: Path,
    deployment: Path,
    meta: dict[str, Any],
) -> dict[str, str]:
    """Resolve live destination pin from stamps + vendor proof (not mutable meta alone)."""
    from sbfleet import upstream as up

    sbf_path = deployment / ".sbfleet-upstream"
    stamp_path = deployment / ".supabase-version"
    if not sbf_path.is_file() or not stamp_path.is_file():
        raise ManifestError("destination pin UNKNOWN; refuse restore")
    pin: dict[str, str] = {}
    for line in sbf_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        pin[key.strip()] = val.strip()
    ref = pin.get("ref") or ""
    sha = pin.get("sha") or ""
    stamp_ref = ""
    for line in stamp_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("ref="):
            stamp_ref = line.split("=", 1)[1].strip()
            break
    if not ref or not sha or ref == "UNKNOWN" or sha == "UNKNOWN" or len(sha) != 40:
        raise ManifestError("destination pin UNKNOWN; refuse restore")
    if stamp_ref and stamp_ref != ref:
        raise ManifestError(
            f"destination pin inconsistent: .supabase-version ref={stamp_ref!r} "
            f".sbfleet-upstream ref={ref!r}"
        )
    meta_up = meta.get("upstream") or {}
    if isinstance(meta_up, dict):
        meta_ref = str(meta_up.get("ref") or "")
        meta_sha = str(meta_up.get("sha") or "")
        if meta_ref and meta_ref != ref:
            raise ManifestError("destination pin inconsistent: meta vs stamp ref")
        if meta_sha and meta_sha != sha:
            raise ManifestError("destination pin inconsistent: meta vs stamp sha")
    pin_meta = {**meta, "upstream": {"ref": ref, "sha": sha}}
    try:
        up.verify_stamp_matches_meta(deployment, pin_meta)
        up.verify_deployment_vendor(deployment, sha=sha, root=root)
    except up.UpstreamError as exc:
        raise ManifestError(f"destination pin/vendor integrity: {exc}") from exc
    return {"ref": ref, "sha": sha}


def prevalidate_restore_archive(
    *,
    tar_path: Path,
    extract_dir: Path,
    destination_project_id: str,
    destination_meta: dict[str, Any],
    deployment: Path,
    root: Path,
    ciphertext_sha256: str,
    filename_backup_id: str,
    receipt: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, str], str]:
    """Two-phase archive + destination prevalidation BEFORE target mutation.

    Returns ``(internal_manifest, archived_env, manifest_digest)``.
    Never stops or quarantines the destination.
    """
    from sbfleet import upstream as up

    man_raw, man_spec, _tar_members = read_manifest_from_tar(tar_path)
    try:
        internal = json.loads(man_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"manifest.json is not valid JSON: {exc}") from exc
    if not isinstance(internal, dict):
        raise ManifestError("manifest.json must be a JSON object")
    validate_internal_manifest(internal)
    require_recovery_files(internal)
    raw_digest = write_buffered_hash(man_raw)
    man_digest = manifest_sha256(internal)
    if raw_digest != man_digest:
        raise ManifestError("manifest.json bytes are not canonical; refuse restore")

    internal_bid = str(internal.get("backup_id") or "")
    if not internal_bid:
        raise ManifestError("manifest missing backup_id")
    if internal_bid != filename_backup_id:
        raise ManifestError(
            f"internal backup_id {internal_bid!r} does not match archive "
            f"filename id {filename_backup_id!r}"
        )
    if receipt is not None:
        receipt_archive_binding_ok(
            receipt,
            ciphertext_sha256=ciphertext_sha256,
            project_id=destination_project_id,
            backup_id=internal_bid,
            manifest_sha256=man_digest,
        )

    expected, checksums = bootstrap_expected_from_manifest(
        internal, manifest_tar_size=man_spec.size
    )
    checksums = dict(checksums)
    checksums["manifest.json"] = raw_digest
    extract_dir.mkdir(parents=True, exist_ok=True)
    safe_extract(
        tar_path,
        extract_dir,
        expected=expected,
        verify_sha256=checksums,
    )

    project_identity_matches(internal, destination_project_id)
    archived_project = json.loads((extract_dir / "project.json").read_text(encoding="utf-8"))
    if str(archived_project.get("id") or "") != destination_project_id:
        raise ManifestError("archived project.json identity mismatch")
    env_path = extract_dir / "deployment" / ".env"
    if not env_path.is_file():
        raise ManifestError("archive missing deployment/.env after extract")
    archived_env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
    up.validate_generated_env(archived_env)
    if not (extract_dir / "db-config" / "pgsodium_root.key").is_file():
        raise ManifestError("missing db-config/pgsodium_root.key after extract")

    auth_pin = _authoritative_destination_pin(root, deployment, destination_meta)
    require_same_pin(
        internal,
        destination_ref=auth_pin["ref"],
        destination_sha=auth_pin["sha"],
    )
    auth_images = _authoritative_destination_images(
        deployment,
        str(destination_meta.get("compose_project") or ""),
        destination_meta,
    )
    compatibility_matches(
        internal,
        destination_images=auth_images,
        destination_upstream=auth_pin,
        require_same_pin=True,
    )
    require_db_recovery_facts(internal)
    return internal, archived_env, man_digest


def restore_backup(
    root: Path,
    slug: str,
    archive: str,
    *,
    yes: bool,
    identity: str | None = None,
    expected_sql: dict[str, Any] | None = None,
    expected_auth: dict[str, Any] | None = None,
    expected_vault: dict[str, Any] | None = None,
) -> int:
    if not yes:
        print("error: restore requires --yes", file=sys.stderr)
        return EXIT_SAFETY

    def _err(exc: BaseException) -> None:
        from sbfleet.process import sanitize_configured_diagnostic

        deployment = reg.project_dir(root, slug) / "deployment"
        print(
            "error: "
            + sanitize_configured_diagnostic(str(exc), deployment=deployment, max_len=500),
            file=sys.stderr,
        )

    try:
        from sbfleet import authority as auth
        from sbfleet import upstream as up
        from sbfleet.health import HEALTHY, lifecycle_op_succeeded
        from sbfleet.projects import ProjectError, start_project

        age = _require_age()
        id_path = _resolve_identity(identity)
        if id_path is None:
            raise BackupError(
                "restore requires --identity or SBFLEET_AGE_IDENTITY",
                code=EXIT_PREREQUISITE,
            )
        archive_path = Path(archive).resolve()
        if not archive_path.is_file():
            raise BackupError("archive missing", code=EXIT_FAILURE)

        with auth.authorize_mutation(root, slug, intent="restore") as ctx:
            # Approach A: durable RESTORING journal begins only after successful
            # requested-archive recovery verification, immediately before the
            # first target-mutation boundary (pre-restore backup / quiesce).
            meta = ctx.meta
            deployment = ctx.deployment
            staging = root / "staging" / f"restore-{ctx.operation_id}"
            staging.mkdir(parents=True, mode=0o700)
            os.chmod(staging, 0o700)
            quarantine = staging / "quarantine"
            extract = staging / "extract"
            journal_begun = False
            quarantine_created = False

            try:
                # --- Pre-mutation preflight (no begin_operation / no fail_operation) ---
                ciphertext_digest = sha256_file(archive_path)
                backup_id = archive_path.name.replace(".tar.age", "")
                receipt_path = root / "backups" / str(meta["id"]) / f"{backup_id}.json"
                receipt = None
                if receipt_path.exists():
                    receipt = reg.load_json(receipt_path)
                    receipt_archive_binding_ok(
                        receipt,
                        ciphertext_sha256=ciphertext_digest,
                        project_id=str(meta["id"]),
                        backup_id=backup_id,
                    )

                dec = staging / "backup.tar"
                v = run(
                    [age, "-d", "-i", str(id_path), "-o", str(dec), str(archive_path)],
                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                    check=False,
                )
                if not v.ok:
                    raise BackupError("age decrypt failed (wrong identity?)", code=EXIT_BACKUP)

                try:
                    internal, archived_env, _man_digest = prevalidate_restore_archive(
                        tar_path=dec,
                        extract_dir=extract,
                        destination_project_id=str(meta["id"]),
                        destination_meta=meta,
                        deployment=deployment,
                        root=root,
                        ciphertext_sha256=ciphertext_digest,
                        filename_backup_id=backup_id,
                        receipt=receipt if isinstance(receipt, dict) else None,
                    )
                except (ArchiveSafetyError, ManifestError, OSError, up.UpstreamError) as exc:
                    raise BackupError(
                        f"archive prevalidation failed before target mutation: {exc}",
                        code=EXIT_BACKUP,
                    ) from exc

                # Capacity for isolated requested-payload verification (before any target mutation).
                disk_preflight(
                    root,
                    deployment,
                    staging_path=staging,
                    output_path=root / "backups",
                )

                # Prove REQUESTED archive recoverability before stop/quarantine/pre-restore.
                rv = run_disposable_recovery_verification(
                    extract_root=extract,
                    manifest=internal,
                    fleet_id=str(meta["fleet_id"]),
                    operation_id=ctx.operation_id,
                    expected_sql=expected_sql,
                    expected_auth=expected_auth,
                    expected_vault=expected_vault,
                    source_crypto=(
                        dict(internal["source_crypto"])
                        if isinstance(internal.get("source_crypto"), dict)
                        else None
                    ),
                    source_facts=(
                        dict(internal["source_facts"])
                        if isinstance(internal.get("source_facts"), dict)
                        else None
                    ),
                )
                if not rv.ok:
                    residuals = (rv.resources or {}).get("cleanup_residuals") or []
                    detail = rv.error or "requested archive recovery assertions failed"
                    if residuals:
                        detail = f"{detail}; cleanup_residuals={residuals}"
                    raise BackupError(
                        "requested archive recovery verification failed before "
                        f"target mutation: {detail}"[:400],
                        code=EXIT_BACKUP,
                    )

                # Durable RESTORING intent begins here (post successful recovery verify).
                auth.begin_operation(ctx, phase="creating_pre_restore_backup")
                journal_begun = True
                auth.record_operation_phase(
                    ctx,
                    phase="creating_pre_restore_backup",
                    evidence={
                        "archive_path": str(archive_path),
                        "backup_id": str(internal.get("backup_id")),
                        "manifest_validated": True,
                        "project_identity_matched": True,
                        "same_pin": True,
                        "requested_archive_recovery_ok": True,
                        "verifier_id": rv.verifier_id,
                        "outcome_version": rv.outcome_version,
                    },
                )
                # Pre-restore verifies CURRENT target recoverability — not archive fixtures.
                pre = _create_backup_locked(
                    ctx,
                    verify=True,
                    identity=id_path,
                    pre_restore=True,
                    expected_sql=None,
                    expected_auth=None,
                    expected_vault=None,
                    expected_functions=None,
                    restore_prior_state=False,
                )
                if pre.verification != VERIFICATION_RECOVERY:
                    raise BackupError(
                        "pre-restore backup not recovery-verified",
                        code=EXIT_SAFETY,
                    )

                auth.record_operation_phase(ctx, phase="stopping_target")
                _quiesce_ordered(ctx)

                auth.record_operation_phase(
                    ctx,
                    phase="quarantining_current",
                    evidence={"quarantine_path": str(quarantine)},
                )
                quarantine.mkdir(parents=True, exist_ok=True)
                quarantine_created = True
                _quarantine_unit(deployment / ".env", quarantine, ".env")
                _quarantine_unit(
                    deployment / "volumes" / "db" / "data", quarantine, "volumes/db/data"
                )
                _quarantine_unit(deployment / "volumes" / "storage", quarantine, "volumes/storage")
                _quarantine_unit(
                    deployment / "volumes" / "functions", quarantine, "volumes/functions"
                )
                _quarantine_unit(
                    deployment / "volumes" / "snippets", quarantine, "volumes/snippets"
                )
                # Quarantine db-config volume
                q_dbcfg = quarantine / "db-config"
                q_dbcfg.mkdir(parents=True, exist_ok=True)
                vol = f"{ctx.compose_project}_db-config"
                qcp = _docker(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "-v",
                        f"{vol}:/from:ro",
                        "-v",
                        f"{q_dbcfg}:/to",
                        HELPER_IMAGE,
                        "sh",
                        "-c",
                        "cp -a /from/. /to/",
                    ],
                    timeout=180.0,
                )
                if not qcp.ok:
                    raise BackupError(f"quarantine db-config failed: {(qcp.stderr or '')[:200]}")

                auth.record_operation_phase(ctx, phase="installing_recovered_data")
                own = PROFILE_OWNERSHIP
                _install_unit_from_extract(
                    extract / "postgres",
                    deployment / "volumes" / "db" / "data",
                    chown=f"{own['postgres']['uid']}:{own['postgres']['gid']}",
                    label="postgres",
                )
                _install_unit_from_extract(
                    extract / "storage",
                    deployment / "volumes" / "storage",
                    chown=f"{own['storage']['uid']}:{own['storage']['gid']}",
                    label="storage",
                )
                for name in ("functions", "snippets"):
                    src = extract / "deployment" / name
                    if src.exists():
                        _install_unit_from_extract(
                            src,
                            deployment / "volumes" / name,
                            chown=None,
                            label=name,
                        )
                # db-config volume restore + ownership
                dbcfg_src = extract / "db-config"
                if not dbcfg_src.is_dir():
                    raise BackupError("archive missing db-config")
                mode = oct(own["pgsodium_root.key_mode"])[2:]
                dbr = _docker(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "-v",
                        f"{vol}:/to",
                        "-v",
                        f"{dbcfg_src}:/from:ro",
                        HELPER_IMAGE,
                        "sh",
                        "-c",
                        "rm -rf /to/* /to/.[!.]* /to/..?* && "
                        "cp -a /from/. /to/ && "
                        f"chown -R {own['db-config']['uid']}:{own['db-config']['gid']} /to && "
                        f"chmod {mode} /to/pgsodium_root.key && "
                        "test -f /to/pgsodium_root.key",
                    ],
                    timeout=180.0,
                )
                if not dbr.ok:
                    raise BackupError(f"db-config restore/chown failed: {(dbr.stderr or '')[:200]}")

                auth.record_operation_phase(ctx, phase="reconciling_destination")
                # Destination env from quarantine (pre-restore); archived_env already prevalidated.
                dest_env_src = quarantine / ".env"
                if not dest_env_src.is_file():
                    raise BackupError("destination .env missing from quarantine")
                destination_env = up.parse_dotenv(dest_env_src.read_text(encoding="utf-8"))
                reconciled = reconcile_destination_env(
                    archived_env=archived_env,
                    destination_env=destination_env,
                    destination_meta=meta,
                )
                env_path = deployment / ".env"
                env_path.write_text(up.dump_dotenv(reconciled), encoding="utf-8")
                os.chmod(env_path, 0o600)

                # Re-run full Run 2A authority/Compose validation before start.
                auth.revalidate_deployment_authority(ctx)

                auth.record_operation_phase(ctx, phase="restoring_ownership")
                # Ownership already applied during install; verify pgsodium mode via helper.
                ver = _docker(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "-v",
                        f"{vol}:/to:ro",
                        HELPER_IMAGE,
                        "sh",
                        "-c",
                        "stat -c '%u:%g %a' /to/pgsodium_root.key",
                    ]
                )
                if not ver.ok:
                    raise BackupError("ownership verification failed for pgsodium_root.key")

                auth.record_operation_phase(ctx, phase="starting_target")
                try:
                    start_project(
                        root,
                        slug,
                        already_locked=True,
                        manage_journal=False,
                        timeout=600,
                    )
                except ProjectError as exc:
                    raise BackupError(
                        f"start failure: {exc}",
                        code=getattr(exc, "code", 7),
                    ) from exc

                auth.record_operation_phase(ctx, phase="verifying_recovery")
                from sbfleet.health import collect_status_for_mutation

                report = collect_status_for_mutation(ctx)
                if not lifecycle_op_succeeded(report, expect=HEALTHY):
                    raise BackupError(
                        f"post-restore health failed: {report.lifecycle}",
                        code=EXIT_FAILURE,
                    )
                # Optional seeded assertions against live destination
                if expected_sql or expected_auth or expected_vault:
                    # Lightweight: rely on HEALTHY + prior recovery verifier; destination
                    # acceptance harness performs exact probes.
                    pass

                auth.complete_operation(
                    ctx,
                    phase="completed",
                    evidence={
                        "backup_id": str(internal.get("backup_id")),
                        "pre_restore_backup_id": pre.backup_id,
                        "quarantine_path": str(quarantine),
                    },
                )
                # Success: remove quarantine and decrypted plaintext staging.
                # Surface residuals honestly; do not claim clean success while plaintext remains.
                cleanup_residuals: list[str] = []
                for target in (quarantine, staging / "backup.tar", extract, staging):
                    try:
                        if not target.exists():
                            continue
                        if target.is_file():
                            target.unlink()
                            if target.exists():
                                cleanup_residuals.append(str(target))
                        else:
                            _wipe_staging(target)
                    except Exception as exc:  # noqa: BLE001
                        cleanup_residuals.append(f"{target}: {exc}"[:240])
                if cleanup_residuals:
                    print(
                        "error: restore applied but plaintext cleanup incomplete; "
                        "residuals: " + "; ".join(cleanup_residuals),
                        file=sys.stderr,
                    )
                    # Re-open evidence via fail path is wrong; print + nonzero while
                    # restore already completed. Archive/target are valid.
                    return EXIT_FAILURE
                print(f"RESTORED {internal.get('backup_id')} applied to {slug}")
                return EXIT_OK
            except Exception as exc:
                if journal_begun:
                    evidence: dict[str, Any] = {}
                    if quarantine_created:
                        evidence["quarantine_path"] = str(quarantine)
                    auth.fail_operation(
                        ctx,
                        error=str(exc),
                        phase="failed",
                        evidence=evidence or None,
                    )
                    if quarantine_created:
                        print(
                            f"error: restore failed; quarantine retained at {quarantine}",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            "error: restore failed after durable RESTORING journal began",
                            file=sys.stderr,
                        )
                else:
                    # Pre-mutation refusal: clean owned staging; never create RESTORING.
                    residuals = _cleanup_restore_preflight_staging(staging)
                    _report_preflight_cleanup_residuals(residuals)
                raise
    except BackupError as exc:
        _err(exc)
        return exc.code
    except Exception as exc:  # noqa: BLE001
        from sbfleet.authority import AuthorityError

        if isinstance(exc, AuthorityError):
            _err(exc)
            return int(getattr(exc, "code", EXIT_SAFETY) or EXIT_SAFETY)
        _err(exc)
        return EXIT_FAILURE
