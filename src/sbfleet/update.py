"""Recovery-gated staged official updates .

Official ``update.sh`` owns configuration transition inside private staging.
sbfleet owns authority, recovery backup, pin selection, env placement reconcile,
override regen, mechanical promotion of an approved staged result, and runtime verify.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.backup_manifest import DESTINATION_OWNED_ENV_KEYS
from sbfleet.cli import EXIT_FAILURE, EXIT_OK, EXIT_PREREQUISITE, EXIT_SAFETY
from sbfleet.process import run

# Finite timeout for official updater subprocess (network fetch + merge).
UPDATER_TIMEOUT_S = 600.0


def _deployment_for_diag(root: Path, slug: str) -> Path | None:
    dep = reg.project_dir(root, slug) / "deployment"
    return dep if dep.is_dir() else None


def _emit_update_error(exc: BaseException, *, deployment: Path | None = None) -> None:
    """Ordinary update/reconcile stderr: configured redact then truncate (V4-002)."""
    from sbfleet.process import sanitize_configured_diagnostic

    print(
        "error: " + sanitize_configured_diagnostic(str(exc), deployment=deployment, max_len=500),
        file=sys.stderr,
    )


# Paths never mechanically promoted from staging onto live (runtime / private / updater junk).
_PROMOTE_EXCLUDE_PREFIXES = (
    "backups/",
    "volumes/db/data",
    "volumes/storage",
    ".run-home/",
    "generated/",
)

# Closed ownership boundary for contract target-surface bind (classification only).
# Not a merge/preserve engine and not an expanding allowlist of "keep local bytes".
# Fleet/generated/runtime-owned paths are excluded from approved-target byte equality;
# everything else present under the approved docker/ snapshot is updater-owned.
_FLEET_RUNTIME_OWNED_EXACT = frozenset(
    {
        "docker-compose.override.yml",
        "docker-compose.sbfleet.yml",
        ".sbfleet-upstream",
        ".env",
        ".supabase-version",
        "test.http",
        # Attribution files copied by sbfleet beside docker/ (not part of docker/ surface).
        "LICENSE",
        "LICENSE.md",
        "COPYING",
    }
)
_FLEET_RUNTIME_OWNED_PREFIXES = (
    ".run-home/",
    "generated/",
    "backups/",
    "volumes/db/data",
    "volumes/storage",
    "volumes/snippets/",
)

# Live authority-surface paths hashed for pre-promotion immutability proofs.
_AUTHORITY_SURFACE_NAMES = (
    "docker-compose.yml",
    "docker-compose.override.yml",
    ".env",
    ".env.example",
    ".supabase-version",
    ".sbfleet-upstream",
    "update.sh",
    "run.sh",
    "setup.sh",
    "docker-compose.sbfleet.yml",
)


class UpdateError(Exception):
    def __init__(self, msg: str, *, code: int = EXIT_FAILURE) -> None:
        super().__init__(msg)
        self.code = code


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hash_authority_surface(deployment: Path) -> dict[str, str]:
    """sha256 map of live vendor/config authority-surface files (missing → absent)."""
    out: dict[str, str] = {}
    for name in _AUTHORITY_SURFACE_NAMES:
        path = deployment / name
        if path.is_file() and not path.is_symlink():
            out[name] = _sha256_file(path)
        else:
            out[name] = "absent"
    return out


def _parse_images(compose_text: str) -> list[str]:
    return re.findall(r"^\s+image:\s*(.+)$", compose_text, flags=re.M)


def _load_upgrades(target_docker: Path) -> dict:
    path = target_docker / "upgrades.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _ver_parts(v: str) -> list[int]:
    return [int(x) for x in v.split(".")]


def _ver_gt(a: str, b: str) -> bool:
    return _ver_parts(a) > _ver_parts(b)


def _ver_le(a: str, b: str) -> bool:
    return _ver_parts(a) <= _ver_parts(b)


def _gate_entries(upgrades: dict, *, from_ref: str, to_ref: str) -> list[dict]:
    """Entries in (from, to] for presentation / blocker listing (not transition authority)."""
    from_v = up.bare_semver(from_ref)
    to_v = up.bare_semver(to_ref)
    refined: list[dict] = []
    for key, entry in upgrades.items():
        if key.startswith("_") or not isinstance(entry, dict):
            continue
        if _ver_gt(key, from_v) and _ver_le(key, to_v):
            refined.append({"version": key, **entry})
    return refined


def _assert_reviewed_transition(from_ref: str, to_ref: str) -> None:
    """Authority is directed REVIEWED_TRANSITIONS only — never semver ordering."""
    if from_ref == to_ref:
        return
    edge = (from_ref, to_ref)
    if edge not in up.REVIEWED_TRANSITIONS:
        raise UpdateError(
            f"unsupported update transition {from_ref!r} → {to_ref!r}; "
            "only explicitly reviewed directed edges are allowed",
            code=EXIT_SAFETY,
        )


def _read_stamp_ref(deployment: Path) -> str:
    path = deployment / ".supabase-version"
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("ref="):
            return line.split("=", 1)[1].strip()
    return ""


def _read_sbfleet_stamp(deployment: Path) -> dict[str, str]:
    path = deployment / ".sbfleet-upstream"
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def detect_vendor_drift(root: Path, deployment: Path, *, from_ref: str, from_sha: str) -> list[str]:
    """Compare critical vendor digests in deployment against source pin cache."""
    cache = up.materialize_cache(root, ref=from_ref, sha=from_sha)
    marker = cache / ".sbfleet-cache.json"
    if not marker.is_file():
        return ["missing-cache-marker"]
    meta = json.loads(marker.read_text(encoding="utf-8"))
    expected = meta.get("critical_digests") or {}
    problems: list[str] = []
    for rel, digest in expected.items():
        path = deployment / rel
        if not path.is_file():
            problems.append(f"missing:{rel}")
            continue
        actual = _sha256_file(path)
        if actual != digest:
            problems.append(f"drift:{rel}")
    return problems


def _same_target_validated_noop(
    root: Path,
    slug: str,
    meta: dict[str, Any],
    *,
    to_ref: str,
    to_sha: str,
) -> tuple[bool, list[str]]:
    """Return (ok, reasons) for same-target verified no-op."""
    reasons: list[str] = []
    upstream = meta.get("upstream") or {}
    if str(upstream.get("ref") or "") != to_ref or str(upstream.get("sha") or "") != to_sha:
        reasons.append("upstream-mismatch")
    verified = meta.get("last_verified_upstream") or {}
    if str(verified.get("ref") or "") != to_ref or str(verified.get("sha") or "") != to_sha:
        reasons.append("last_verified-mismatch")
    journal = reg.read_operation_journal(root, slug)
    if reg.journal_is_unresolved(journal):
        reasons.append("unresolved-update-journal")
    deployment = reg.project_dir(root, slug) / "deployment"
    stamp_ref = _read_stamp_ref(deployment)
    if stamp_ref and stamp_ref != to_ref:
        reasons.append("supabase-version-mismatch")
    sbf = _read_sbfleet_stamp(deployment)
    if sbf.get("ref") and sbf.get("ref") != to_ref:
        reasons.append("sbfleet-stamp-ref-mismatch")
    if sbf.get("sha") and sbf.get("sha") != to_sha:
        reasons.append("sbfleet-stamp-sha-mismatch")
    drift = detect_vendor_drift(root, deployment, from_ref=to_ref, from_sha=to_sha)
    if drift:
        reasons.append("vendor-drift:" + ",".join(drift[:5]))
    return (not reasons, reasons)


def _reviewed_plans_equivalent(reviewed: dict, locked: dict) -> bool:
    """Operator authorization for plan A is not authorization for plan B."""
    rd = reviewed.get("data") or {}
    ld = locked.get("data") or {}
    keys = (
        "to_ref",
        "to_sha",
        "noop",
    )
    for key in keys:
        if rd.get(key) != ld.get(key):
            return False
    rf = rd.get("from") or {}
    lf = ld.get("from") or {}
    if str(rf.get("ref") or "") != str(lf.get("ref") or ""):
        return False
    if str(rf.get("sha") or "") != str(lf.get("sha") or ""):
        return False
    if bool(reviewed.get("ok")) != bool(locked.get("ok")):
        return False
    rb = list(rd.get("blockers") or rd.get("manual_gates") or [])
    lb = list(ld.get("blockers") or ld.get("manual_gates") or [])
    if rb != lb:
        return False
    return True


def build_plan(
    root: Path,
    slug: str,
    *,
    to_ref: str,
) -> dict:
    if not to_ref:
        raise UpdateError("update requires explicit --to REF", code=EXIT_SAFETY)
    meta = reg.read_project(root, slug)
    from_info = meta.get("upstream") or {}
    from_ref = str(from_info.get("ref") or "")
    from_sha = str(from_info.get("sha") or "")
    if not from_ref or not from_sha:
        raise UpdateError("project missing upstream metadata", code=EXIT_SAFETY)
    up.validate_ref(to_ref)
    to_sha = up.resolve_ref_sha(to_ref)

    if from_ref == to_ref and from_sha == to_sha:
        ok_noop, reasons = _same_target_validated_noop(
            root, slug, meta, to_ref=to_ref, to_sha=to_sha
        )
        return {
            "format_version": 1,
            "ok": ok_noop,
            "command": "update",
            "data": {
                "slug": slug,
                "from": from_info,
                "to_ref": to_ref,
                "to_sha": to_sha,
                "noop": True,
                "noop_validated": ok_noop,
                "noop_blockers": reasons,
                "requires_backup": False,
                "manual_gates": [],
                "dry_run": True,
            },
            "warnings": (
                ["same-ref no-op — does not fulfill transition acceptance"] if ok_noop else []
            ),
            "errors": ([] if ok_noop else [f"same-target no-op refused: {r}" for r in reasons]),
        }

    _assert_reviewed_transition(from_ref, to_ref)

    target_cache = up.materialize_cache(root, ref=to_ref, sha=to_sha)
    from_cache = up.materialize_cache(root, ref=from_ref, sha=from_sha)
    from_compose = (from_cache / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    to_compose = (target_cache / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    from_imgs = _parse_images(from_compose)
    to_imgs = _parse_images(to_compose)
    image_diffs = [{"from": a, "to": b} for a, b in zip(from_imgs, to_imgs, strict=False) if a != b]
    if len(from_imgs) != len(to_imgs):
        raise UpdateError(
            "service/image inventory shape changed — BLOCKED_ARCHITECTURE for automated update",
            code=EXIT_SAFETY,
        )
    upgrades = _load_upgrades(target_cache / "docker")
    gates = _gate_entries(upgrades, from_ref=from_ref, to_ref=to_ref)
    blockers = []
    for g in gates:
        if g.get("breaking") or g.get("gate"):
            blockers.append(g)
    return {
        "format_version": 1,
        "ok": not blockers,
        "command": "update",
        "data": {
            "slug": slug,
            "from": from_info,
            "to_ref": to_ref,
            "to_sha": to_sha,
            "noop": False,
            "requires_backup": True,
            "manual_gates": gates,
            "blockers": blockers,
            "image_diffs": image_diffs,
            "reviewed_edge": [from_ref, to_ref],
            "dry_run": True,
        },
        "warnings": [],
        "errors": [
            f"manual gate {b.get('version')}: breaking/gate requires human upgrade path"
            for b in blockers
        ],
    }


def _seed_staging(deployment: Path, staging: Path) -> None:
    """Copy config-only tree into private staging (no live data binds)."""
    staging.mkdir(parents=True, mode=0o700)
    os.chmod(staging, 0o700)

    def _ignore(directory: str, names: list[str]) -> set[str]:
        ignored: set[str] = set()
        dpath = Path(directory)
        rel = dpath.relative_to(deployment) if dpath != deployment else Path(".")
        rel_s = str(rel).replace("\\", "/")
        for name in names:
            child = f"{rel_s}/{name}" if rel_s != "." else name
            child = child.replace("\\", "/")
            if child in {"volumes/db/data", "volumes/storage", ".run-home", "generated"}:
                ignored.add(name)
            if child.startswith("volumes/db/data/") or child.startswith("volumes/storage/"):
                ignored.add(name)
            if name in {".run-home", "generated"} and rel_s == ".":
                ignored.add(name)
            if rel_s == "volumes" and name == "storage":
                ignored.add(name)
            if rel_s == "volumes/db" and name == "data":
                ignored.add(name)
            if name == "backups" and rel_s == ".":
                ignored.add(name)
        return ignored

    # Prefer shutil.copytree into empty staging content dir.
    for item in deployment.iterdir():
        name = item.name
        if name in {".run-home", "generated", "backups"}:
            continue
        if name == "volumes":
            vol_dest = staging / "volumes"
            vol_dest.mkdir(parents=True, exist_ok=True)
            for sub in item.iterdir():
                if sub.name in {"storage"}:
                    continue
                if sub.name == "db":
                    db_dest = vol_dest / "db"
                    db_dest.mkdir(parents=True, exist_ok=True)
                    for db_child in sub.iterdir():
                        if db_child.name == "data":
                            continue
                        if db_child.is_dir():
                            shutil.copytree(
                                db_child,
                                db_dest / db_child.name,
                                symlinks=False,
                                ignore=_ignore,
                            )
                        elif db_child.is_file() and not db_child.is_symlink():
                            shutil.copy2(db_child, db_dest / db_child.name)
                    continue
                if sub.is_dir():
                    shutil.copytree(sub, vol_dest / sub.name, symlinks=False, ignore=_ignore)
                elif sub.is_file() and not sub.is_symlink():
                    shutil.copy2(sub, vol_dest / sub.name)
            continue
        if item.is_symlink():
            raise UpdateError(f"refusing symlink in deployment seed: {name}", code=EXIT_SAFETY)
        if item.is_dir():
            shutil.copytree(item, staging / name, symlinks=False, ignore=_ignore)
        elif item.is_file():
            shutil.copy2(item, staging / name)

    # Ensure staging has no data dirs / restrictive perms.
    os.chmod(staging, 0o700)
    (staging / "backups").mkdir(mode=0o700, exist_ok=True)


def _place_source_updater(root: Path, staging: Path, *, from_ref: str, from_sha: str) -> Path:
    cache = up.materialize_cache(root, ref=from_ref, sha=from_sha)
    src = cache / "docker" / "update.sh"
    if not src.is_file():
        raise UpdateError("source pin missing update.sh", code=EXIT_SAFETY)
    digest = _sha256_file(src)
    if digest != up.UPDATE_SH_SOURCE_SHA256 and from_ref == "self-hosted/v0.8.1":
        raise UpdateError(
            f"source update.sh digest mismatch: {digest[:16]}…",
            code=EXIT_SAFETY,
        )
    dest = staging / "update.sh"
    shutil.copy2(src, dest)
    os.chmod(dest, 0o700)
    return dest


def _updater_env(staging: Path) -> dict[str, str]:
    home = staging / ".run-home"
    home.mkdir(mode=0o700, exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "LC_ALL": "C",
        "SUPABASE_REPO_URL": up.OFFICIAL_REPO.removesuffix(".git"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
    }


def run_official_updater(
    staging: Path,
    *,
    to_ref: str,
    timeout: float = UPDATER_TIMEOUT_S,
) -> Any:
    """Invoke contract-matched ``sh update.sh --to <ref>`` in staging (stdin closed)."""
    argv = ["sh", "update.sh", "--to", to_ref]
    return run(
        argv,
        cwd=staging,
        env=_updater_env(staging),
        timeout=timeout,
        check=False,
        input_data=None,  # stdin DEVNULL when no input
    )


def _redact_updater_output(text: str, secrets: dict[str, str | None]) -> str:
    from sbfleet.process import Redactor, sanitize_diagnostic

    redactor = Redactor()
    redactor.add_many(list(secrets.values()))
    return sanitize_diagnostic(text or "", redactor=redactor)


def inspect_updater_result(
    staging: Path,
    result: Any,
    *,
    to_ref: str,
    to_sha: str,
) -> None:
    """Fail-closed inspection of official updater outcome (not exit-code alone)."""
    # to_sha is an enforced fact: stamp-ref alone never authorizes a retargeted tag.
    try:
        approved = up.resolve_ref_sha(to_ref)
    except up.UpstreamError as exc:
        raise UpdateError(str(exc), code=EXIT_SAFETY) from exc
    if to_sha != approved:
        raise UpdateError(
            f"to_sha {to_sha} does not match approved SHA for {to_ref} ({approved})",
            code=EXIT_SAFETY,
        )

    if getattr(result, "timed_out", False):
        raise UpdateError(
            f"official updater timed out after {UPDATER_TIMEOUT_S}s",
            code=EXIT_FAILURE,
        )
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    combined = stdout + "\n" + stderr

    # Conflict markers anywhere in staged files or report.
    if "CONFLICTS:" in combined:
        # Parse count if present
        m = re.search(r"CONFLICTS:\s*(\d+)", combined)
        if m and int(m.group(1)) > 0:
            raise UpdateError(
                "official updater reported merge CONFLICTS; refusing promotion",
                code=EXIT_SAFETY,
            )
    if "merge failures:" in combined:
        m = re.search(r"merge failures:\s*(\d+)", combined)
        if m and int(m.group(1)) > 0:
            raise UpdateError(
                "official updater reported merge failures; refusing promotion",
                code=EXIT_SAFETY,
            )

    # Conflict markers in staged files (real merge markers, not docs mentioning them).
    marker_re = re.compile(rb"(?m)^<<<<<<< ")
    end_re = re.compile(rb"(?m)^>>>>>>> ")
    for path in staging.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = str(path.relative_to(staging)).replace("\\", "/")
        if rel.startswith("backups/") or rel.startswith(".run-home/"):
            continue
        # Official update.sh documents marker syntax in warn strings — skip self.
        if rel in {"update.sh", "update.sh.dist"}:
            continue
        try:
            sample = path.read_bytes()[:200_000]
        except OSError:
            continue
        if marker_re.search(sample) and end_re.search(sample):
            raise UpdateError(
                f"conflict markers in staged file {rel}; refusing promotion",
                code=EXIT_SAFETY,
            )

    dist = staging / "update.sh.dist"
    if dist.is_file():
        raise UpdateError(
            "update.sh.dist present — updater self-update requires manual reconciliation",
            code=EXIT_SAFETY,
        )

    if result.returncode == 2:
        raise UpdateError(
            "official updater exited 2 (conflicts); refusing promotion",
            code=EXIT_SAFETY,
        )
    if result.returncode != 0:
        raise UpdateError(
            f"official updater exited {result.returncode}",
            code=EXIT_FAILURE,
        )

    # Stamp must advance to target ref on clean apply.
    stamp_ref = _read_stamp_ref(staging)
    if stamp_ref != to_ref:
        raise UpdateError(
            f"staged .supabase-version ref={stamp_ref!r} != target {to_ref!r}",
            code=EXIT_SAFETY,
        )


def is_fleet_or_runtime_owned(rel: str, *, approved_target_files: set[str] | None = None) -> bool:
    """Closed ownership boundary: fleet/generated/runtime paths are not updater-owned."""
    rel = rel.replace("\\", "/")
    if rel in _FLEET_RUNTIME_OWNED_EXACT:
        return True
    for prefix in _FLEET_RUNTIME_OWNED_PREFIXES:
        bare = prefix.rstrip("/")
        if rel == bare or rel.startswith(bare + "/"):
            return True
    # Custom function bodies live under volumes/functions/ but are user-owned unless
    # present in the approved target snapshot (upstream .gitignore exceptions).
    if (
        approved_target_files is not None
        and rel.startswith("volumes/functions/")
        and rel not in approved_target_files
    ):
        return True
    return False


def _inventory_regular_files(root: Path) -> dict[str, Path]:
    """Map relative path → path for regular (non-symlink) files under root."""
    out: dict[str, Path] = {}
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Never descend into .git or private staging homes.
        dirnames[:] = [d for d in dirnames if d not in {".git", ".run-home"}]
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            rel = str(path.relative_to(root)).replace("\\", "/")
            if path.is_symlink():
                raise UpdateError(
                    f"refusing symlink in target-surface inventory: {rel}",
                    code=EXIT_SAFETY,
                )
            if not path.is_file():
                continue
            out[rel] = path
    return out


def bind_staging_to_approved_target(
    root: Path,
    staging: Path,
    *,
    to_ref: str,
    to_sha: str,
    from_ref: str | None = None,
    from_sha: str | None = None,
) -> Path:
    """Bind complete updater-owned staged vendor surface to approved target at to_sha.

    Stronger than contract critical-cache digests: every updater-owned regular file
    must match the approved target snapshot (expected set, additions, removals,
    types, hashes). Fleet/runtime-owned paths use a closed ownership boundary.
    """
    try:
        up.validate_ref(to_ref)
        up.validate_sha(to_sha)
        approved_to = up.resolve_ref_sha(to_ref)
    except up.UpstreamError as exc:
        raise UpdateError(str(exc), code=EXIT_SAFETY) from exc
    if to_sha != approved_to:
        raise UpdateError(
            f"target ref↔SHA mismatch: {to_ref} → approved {approved_to}, got {to_sha}",
            code=EXIT_SAFETY,
        )
    if from_ref is not None and from_sha is not None:
        try:
            up.validate_ref(from_ref)
            up.validate_sha(from_sha)
            approved_from = up.resolve_ref_sha(from_ref)
        except up.UpstreamError as exc:
            raise UpdateError(str(exc), code=EXIT_SAFETY) from exc
        if from_sha != approved_from:
            raise UpdateError(
                f"source ref↔SHA mismatch: {from_ref} → approved {approved_from}, got {from_sha}",
                code=EXIT_SAFETY,
            )

    try:
        target_cache = up.materialize_cache(root, ref=to_ref, sha=to_sha)
    except up.UpstreamError as exc:
        raise UpdateError(
            f"approved target cache unavailable for {to_ref}@{to_sha[:12]}: {exc}",
            code=EXIT_SAFETY,
        ) from exc

    target_docker = target_cache / "docker"
    if not target_docker.is_dir() or target_docker.is_symlink():
        raise UpdateError("approved target cache missing docker/", code=EXIT_SAFETY)

    approved_files = _inventory_regular_files(target_docker)
    approved_keys = set(approved_files)
    staged_files = _inventory_regular_files(staging)

    # Expected updater-owned surface = approved target minus closed ownership boundary.
    expected = {
        rel
        for rel in approved_keys
        if not is_fleet_or_runtime_owned(rel, approved_target_files=approved_keys)
    }
    # Staged updater-owned = staged regular files outside ownership boundary.
    staged_owned = {
        rel
        for rel in staged_files
        if not is_fleet_or_runtime_owned(rel, approved_target_files=approved_keys)
    }

    missing = sorted(expected - staged_owned)
    if missing:
        raise UpdateError(
            "staged updater surface missing approved target file(s): " + ", ".join(missing[:8]),
            code=EXIT_SAFETY,
        )
    extra = sorted(staged_owned - expected)
    if extra:
        raise UpdateError(
            "unexpected staged upstream-owned file(s): " + ", ".join(extra[:8]),
            code=EXIT_SAFETY,
        )

    for rel in sorted(expected):
        src = staged_files[rel]
        tgt = approved_files[rel]
        # Type check: both must be regular non-symlink files (inventory already filters).
        if src.is_symlink() or tgt.is_symlink() or not src.is_file() or not tgt.is_file():
            raise UpdateError(
                f"updater-owned path type mismatch for {rel}",
                code=EXIT_SAFETY,
            )
        actual = _sha256_file(src)
        wanted = _sha256_file(tgt)
        if actual != wanted:
            raise UpdateError(
                f"staged updater-owned digest mismatch for {rel}: "
                f"{actual[:12]}!={wanted[:12]} (approved {to_sha[:12]})",
                code=EXIT_SAFETY,
            )

    return target_cache


def reconcile_update_env(
    *,
    staged_env: dict[str, str],
    destination_env: dict[str, str],
    destination_meta: dict[str, Any],
    before_secrets: dict[str, str | None],
) -> dict[str, str]:
    """Preserve destination-owned placement; keep secrets; refuse unsafe new defaults."""
    from sbfleet.backup import reconcile_destination_env

    # Start from destination placement merge of staged secrets + destination authority.
    out = reconcile_destination_env(
        archived_env=staged_env,
        destination_env=destination_env,
        destination_meta=destination_meta,
    )
    # Bring any non-secret, non-destination keys newly introduced by updater.
    secretish_tokens = ("PASSWORD", "SECRET", "KEY", "TOKEN", "JWT")
    for key, val in staged_env.items():
        if key in out:
            continue
        if key in DESTINATION_OWNED_ENV_KEYS:
            continue
        if key in up.REQUIRED_ENV_KEYS or any(s in key.upper() for s in secretish_tokens):
            if not val or val.startswith("your-") or val in {"changeme", "replace-me"}:
                raise UpdateError(
                    f"new required secret key {key} lacks a safe value after update",
                    code=EXIT_SAFETY,
                )
        out[key] = val

    # Existing secrets must not change.
    for k, before in before_secrets.items():
        if before is None:
            continue
        if out.get(k) != before:
            raise UpdateError(
                f"secret {k} changed during update — refusing",
                code=EXIT_SAFETY,
            )

    out["COMPOSE_FILE"] = "docker-compose.yml:docker-compose.override.yml"
    up.validate_generated_env(out)
    return out


# Canonical promote-record basename (never mechanically promoted onto live).
PROMOTE_RECORD_NAME = "promote-record.json"
PROMOTE_RECORD_FORMAT = 1
PROGRESS_INTENDED = "intended"
PROGRESS_PREPARED = "prepared"
PROGRESS_VERIFIED = "verified"
KIND_ABSENT = "absent"
KIND_REGULAR_FILE = "regular_file"
CLASS_EXACT_SOURCE = "exact_source"
CLASS_EXACT_TARGET = "exact_target"
CLASS_MISSING = "missing"
CLASS_FOREIGN = "foreign_unknown"


def _promote_excluded(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    if rel == PROMOTE_RECORD_NAME or rel.startswith(PROMOTE_RECORD_NAME + "/"):
        return True
    for prefix in _PROMOTE_EXCLUDE_PREFIXES:
        if rel == prefix.rstrip("/") or rel.startswith(prefix):
            return True
    return False


def promote_record_path(staging: Path) -> Path:
    """Operation-scoped canonical recovery record (under update staging)."""
    return staging / PROMOTE_RECORD_NAME


def observe_path_state(path: Path) -> dict[str, Any]:
    """Bounded type/state observation for promote plan / reconcile (no contents)."""
    if path.is_symlink():
        return {"kind": "symlink"}
    if not path.exists():
        return {"kind": KIND_ABSENT}
    if path.is_file():
        mode = stat.S_IMODE(path.stat().st_mode)
        return {
            "kind": KIND_REGULAR_FILE,
            "sha256": _sha256_file(path),
            "mode": mode,
        }
    if path.is_dir():
        return {"kind": "directory"}
    return {"kind": "special"}


def path_states_equal(
    a: Mapping[str, Any] | dict[str, Any], b: Mapping[str, Any] | dict[str, Any]
) -> bool:
    """Compare exact path states (kind + hash for regular files; mode is recorded separately)."""
    ka = str(a.get("kind") or "")
    kb = str(b.get("kind") or "")
    if ka != kb:
        return False
    if ka == KIND_ABSENT:
        return True
    if ka == KIND_REGULAR_FILE:
        return str(a.get("sha256") or "") == str(b.get("sha256") or "")
    return False


def list_promote_relpaths(staging: Path) -> list[str]:
    """Mechanical promote inventory: regular files under staging minus excludes."""
    paths: list[str] = []
    for root, dirs, files in os.walk(staging):
        rel_root = Path(root).relative_to(staging)
        # Prune excluded dirs
        pruned: list[str] = []
        for d in list(dirs):
            rel = str(rel_root / d).replace("\\", "/")
            if _promote_excluded(rel):
                pruned.append(d)
        for d in pruned:
            dirs.remove(d)
        for name in files:
            rel = str(rel_root / name).replace("\\", "/")
            if rel in {".", ""}:
                continue
            if _promote_excluded(rel):
                continue
            src = Path(root) / name
            if src.is_symlink():
                raise UpdateError(
                    f"refusing symlink in staged promote set: {rel}",
                    code=EXIT_SAFETY,
                )
            if not src.is_file():
                continue
            paths.append(rel)
    paths.sort()
    return paths


def build_promote_record(
    *,
    operation_id: str,
    from_ref: str,
    from_sha: str,
    to_ref: str,
    to_sha: str,
    backup_id: str,
    staging: Path,
    deployment: Path,
    quarantine: Path,
    relpaths: list[str],
) -> dict[str, Any]:
    """Immutable intended plan + progress slots from approved staging + live pre-states.

    Built before first live mutation; never derived from post-crash mixed live tree.
    """
    paths: list[dict[str, Any]] = []
    for rel in relpaths:
        src = staging / rel
        tgt_state = observe_path_state(src)
        if tgt_state.get("kind") != KIND_REGULAR_FILE:
            raise UpdateError(
                f"staged promote path must be regular file: {rel} kind={tgt_state.get('kind')}",
                code=EXIT_SAFETY,
            )
        pre = observe_path_state(deployment / rel)
        if pre.get("kind") not in {KIND_ABSENT, KIND_REGULAR_FILE}:
            raise UpdateError(
                f"refuse promote over unexpected live type for {rel}: {pre.get('kind')}",
                code=EXIT_SAFETY,
            )
        paths.append(
            {
                "rel": rel,
                "pre": pre,
                "target": tgt_state,
                "progress": PROGRESS_INTENDED,
            }
        )
    return {
        "format_version": PROMOTE_RECORD_FORMAT,
        "operation_id": operation_id,
        "from_ref": from_ref,
        "from_sha": from_sha,
        "to_ref": to_ref,
        "to_sha": to_sha,
        "backup_id": backup_id,
        "staging_path": str(staging),
        "quarantine_path": str(quarantine),
        "promotion_begun": False,
        "paths_promoted_complete": False,
        "metadata_advanced": False,
        "runtime_verified": False,
        "paths": paths,
    }


def write_promote_record(staging: Path, record: Mapping[str, Any]) -> Path:
    """Crash-safe canonical write (operation-scoped under staging)."""
    path = promote_record_path(staging)
    staging.mkdir(parents=True, exist_ok=True)
    os.chmod(staging, 0o700)
    reg.atomic_write_json(path, dict(record), mode=0o600)
    return path


def load_promote_record(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise UpdateError(f"promote record missing: {path}", code=EXIT_SAFETY)
    data = reg.load_json(path)
    if not isinstance(data, dict):
        raise UpdateError("promote record must be a JSON object", code=EXIT_SAFETY)
    if int(data.get("format_version") or 0) != PROMOTE_RECORD_FORMAT:
        raise UpdateError("unsupported promote record format", code=EXIT_SAFETY)
    if not str(data.get("operation_id") or ""):
        raise UpdateError("promote record missing operation_id", code=EXIT_SAFETY)
    if not isinstance(data.get("paths"), list):
        raise UpdateError("promote record missing paths", code=EXIT_SAFETY)
    return data


def update_promote_path_progress(
    staging: Path,
    record: dict[str, Any],
    *,
    rel: str,
    progress: str,
    **flags: Any,
) -> dict[str, Any]:
    """Persist per-path progress on the canonical record before any journal summary."""
    found = False
    for entry in record["paths"]:
        if entry.get("rel") == rel:
            entry["progress"] = progress
            found = True
            break
    if not found:
        raise UpdateError(f"promote record missing path {rel}", code=EXIT_SAFETY)
    for key, value in flags.items():
        record[key] = value
    write_promote_record(staging, record)
    return record


def set_promote_record_flags(staging: Path, record: dict[str, Any], **flags: Any) -> dict[str, Any]:
    for key, value in flags.items():
        record[key] = value
    write_promote_record(staging, record)
    return record


def classify_live_path(
    live: Mapping[str, Any], pre: Mapping[str, Any], target: Mapping[str, Any]
) -> str:
    """Classify live path against frozen pre/target states (type/state/hash)."""
    kind = str(live.get("kind") or "")
    if kind not in {KIND_ABSENT, KIND_REGULAR_FILE}:
        return CLASS_FOREIGN
    if path_states_equal(live, target):
        return CLASS_EXACT_TARGET
    if path_states_equal(live, pre):
        return CLASS_EXACT_SOURCE
    if kind == KIND_ABSENT:
        return CLASS_MISSING
    return CLASS_FOREIGN


def diagnose_promote_paths(deployment: Path, record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Inspect live paths against frozen plan; journal progress is ignored."""
    out: list[dict[str, Any]] = []
    for entry in record.get("paths") or []:
        rel = str(entry.get("rel") or "")
        pre = entry.get("pre") if isinstance(entry.get("pre"), dict) else {}
        target = entry.get("target") if isinstance(entry.get("target"), dict) else {}
        live = observe_path_state(deployment / rel)
        classification = classify_live_path(live, pre, target)
        out.append(
            {
                "rel": rel,
                "classification": classification,
                "live_kind": live.get("kind"),
                "record_progress": entry.get("progress"),
            }
        )
    return out


def promotion_phase_label(record: Mapping[str, Any], diagnoses: list[dict[str, Any]]) -> str:
    """Coarse crash-phase label from canonical record + live diagnosis."""
    if not diagnoses:
        return "no_promotion_paths"
    verified = [d for d in diagnoses if d["classification"] == CLASS_EXACT_TARGET]
    source = [d for d in diagnoses if d["classification"] == CLASS_EXACT_SOURCE]
    foreign = [d for d in diagnoses if d["classification"] == CLASS_FOREIGN]
    if foreign:
        return "foreign_or_unexpected"
    if not verified and source and len(source) == len(diagnoses):
        return "no_promotion_began"
    if verified and source:
        return "partially_promoted"
    if len(verified) == len(diagnoses):
        if record.get("runtime_verified"):
            return "runtime_verified_journal_incomplete"
        if record.get("metadata_advanced") or record.get("paths_promoted_complete"):
            return "promotion_complete_verify_incomplete"
        return "promotion_complete_verify_incomplete"
    return "partially_promoted"


def mechanical_promote(
    staging: Path,
    deployment: Path,
    *,
    record: dict[str, Any],
    quarantine: Path,
    crash_hook: Any | None = None,
) -> list[str]:
    """Replace live files with approved staged bytes. Durable progress on promote-record.

    Uses host atomic replace when permitted; falls back to a network-none Docker
    helper for container-owned volume trees (checked result, no silent ignore).

    Canonical record is updated before any journal summary. ``crash_hook(rel, phase)``
    may be injected by process-death tests (phases: after_record, after_first,
    mid_after_n, after_all_files).
    """
    quarantine.mkdir(parents=True, mode=0o700)
    os.chmod(quarantine, 0o700)
    set_promote_record_flags(staging, record, promotion_begun=True)
    if crash_hook is not None:
        crash_hook("__record__", "after_record")

    completed: list[str] = []
    entries = list(record["paths"])
    for idx, entry in enumerate(entries):
        rel = str(entry["rel"])
        src = staging / rel
        dest = deployment / rel
        target = entry["target"]
        if not src.is_file() or src.is_symlink():
            raise UpdateError(f"staged path missing for promote: {rel}", code=EXIT_FAILURE)
        update_promote_path_progress(staging, record, rel=rel, progress=PROGRESS_PREPARED)

        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() or dest.is_symlink():
            qdest = quarantine / rel
            qdest.parent.mkdir(parents=True, exist_ok=True)
            if dest.is_symlink() or not dest.is_file():
                raise UpdateError(f"refuse promote over non-file: {rel}", code=EXIT_SAFETY)
            try:
                shutil.copy2(dest, qdest)
            except PermissionError:
                _docker_copy_file(dest, qdest)
        tmp = dest.with_name(dest.name + ".sbfleet-promote-tmp")
        try:
            try:
                shutil.copy2(src, tmp)
                mode = src.stat().st_mode
                os.chmod(tmp, stat.S_IMODE(mode))
                os.replace(tmp, dest)
            except PermissionError:
                if tmp.exists():
                    tmp.unlink(missing_ok=True)
                _docker_copy_file(src, dest)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass

        live = observe_path_state(dest)
        if not path_states_equal(live, target):
            raise UpdateError(
                f"post-promote verify failed for {rel}: live={live.get('kind')} "
                f"expected regular_file sha={str(target.get('sha256') or '')[:12]}",
                code=EXIT_SAFETY,
            )
        update_promote_path_progress(staging, record, rel=rel, progress=PROGRESS_VERIFIED)
        completed.append(rel)
        if crash_hook is not None:
            if idx == 0:
                crash_hook(rel, "after_first")
            crash_hook(rel, f"mid_after_{idx + 1}")

    set_promote_record_flags(staging, record, paths_promoted_complete=True)
    if crash_hook is not None:
        crash_hook("__all__", "after_all_files")
    return completed


def _docker_copy_file(src: Path, dest: Path) -> None:
    """Checked single-file copy via alpine helper (container-owned destinations)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{src.parent}:/from:ro",
            "-v",
            f"{dest.parent}:/to",
            "alpine:3.20",
            "sh",
            "-c",
            f"cp -f /from/{src.name} /to/{dest.name}",
        ],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=120.0,
        check=False,
    )
    if not r.ok:
        raise UpdateError(
            f"docker promote copy failed for {dest.name}: {(r.stderr or '')[:200]}",
            code=EXIT_FAILURE,
        )


def _wipe_update_staging(staging: Path) -> None:
    """Wipe update staging via the shared checked deletion boundary.

    Mount/ownership refusal is terminal — never fall back to unguarded rmtree.
    """
    if not staging.exists():
        return
    from sbfleet.backup import _wipe_staging

    _wipe_staging(staging)


def update_project(
    root: Path,
    slug: str,
    *,
    to_ref: str | None,
    dry_run: bool,
    yes: bool,
    identity: str | None = None,
    reconcile: bool = False,
    operation_id: str | None = None,
) -> int:
    if reconcile:
        if dry_run:
            print("error: --reconcile does not support --dry-run", file=sys.stderr)
            return EXIT_SAFETY
        if to_ref:
            print("error: --reconcile cannot be combined with --to", file=sys.stderr)
            return EXIT_SAFETY
        if not operation_id:
            print("error: --reconcile requires --operation-id", file=sys.stderr)
            return EXIT_SAFETY
        if not yes:
            print(
                "error: update --reconcile requires --yes after reviewing diagnosis",
                file=sys.stderr,
            )
            return EXIT_SAFETY
        return reconcile_interrupted_update(root, slug, operation_id=operation_id, yes=yes)
    if not to_ref:
        print("error: update requires explicit --to REF", file=sys.stderr)
        return EXIT_SAFETY
    try:
        plan = build_plan(root, slug, to_ref=to_ref)
        if dry_run:
            # Read-only plan: no backup, stop/start, journal mutation, promote, or last_verified.
            print(json.dumps(plan, indent=2, sort_keys=True))
            return EXIT_OK if plan.get("ok") else EXIT_SAFETY

        if plan.get("data", {}).get("noop"):
            if not plan.get("ok"):
                print("error: same-target update refused", file=sys.stderr)
                print(json.dumps(plan, indent=2, sort_keys=True), file=sys.stderr)
                return EXIT_SAFETY
            print(json.dumps({"ok": True, "updated": False, "noop": True, "validated": True}))
            return EXIT_OK

        if not plan.get("ok") or plan.get("data", {}).get("blockers"):
            print("error: update blocked by manual/breaking gates", file=sys.stderr)
            print(json.dumps(plan, indent=2, sort_keys=True), file=sys.stderr)
            return EXIT_SAFETY
        if not yes:
            print("error: update requires --yes after reviewing plan", file=sys.stderr)
            return EXIT_SAFETY

        to_sha = str(plan["data"]["to_sha"])
        from_ref = str(plan["data"]["from"]["ref"])
        from_sha = str(plan["data"]["from"]["sha"])
        target = to_ref

        from sbfleet import authority as auth
        from sbfleet.backup import (
            VERIFICATION_RECOVERY,
            BackupError,
            _capture_prior_state,
            _create_backup_locked,
            is_recovery_verified_receipt,
            load_backup_receipt,
        )
        from sbfleet.health import HEALTHY, STOPPED
        from sbfleet.projects import ProjectError, start_project, stop_project

        with auth.authorize_mutation(root, slug, intent="update") as ctx:
            meta = ctx.meta
            deployment = ctx.deployment
            # Rebuild plan from locked metadata — operator auth for pre-lock plan A
            # is not authorization for a drifted plan B.
            locked_plan = build_plan(root, slug, to_ref=to_ref)
            if not _reviewed_plans_equivalent(plan, locked_plan):
                print(
                    "error: locked update plan differs from the reviewed plan; "
                    "refusing apply. Re-invoke after reviewing the authoritative plan.",
                    file=sys.stderr,
                )
                print(json.dumps(locked_plan, indent=2, sort_keys=True), file=sys.stderr)
                return EXIT_SAFETY
            if not locked_plan.get("ok") or locked_plan.get("data", {}).get("blockers"):
                print(
                    "error: update blocked by manual/breaking gates (locked plan)",
                    file=sys.stderr,
                )
                print(json.dumps(locked_plan, indent=2, sort_keys=True), file=sys.stderr)
                return EXIT_SAFETY
            plan = locked_plan
            to_sha = str(plan["data"]["to_sha"])
            from_ref = str(plan["data"]["from"]["ref"])
            from_sha = str(plan["data"]["from"]["sha"])
            target = to_ref

            auth.begin_operation(ctx, phase="planning")
            staging: Path | None = None
            quarantine: Path | None = None
            promotion_begun = False
            prior_state = STOPPED
            backup_id: str | None = None
            live_hashes_before: dict[str, str] = {}
            before_secrets: dict[str, str | None] = {}

            try:
                # Revalidate edge under lock using locked plan facts.
                _assert_reviewed_transition(from_ref, target)
                drift = detect_vendor_drift(root, deployment, from_ref=from_ref, from_sha=from_sha)
                if drift:
                    raise UpdateError(
                        f"source vendor drift vs pin: {drift[:5]}",
                        code=EXIT_SAFETY,
                    )
                stamp_ref = _read_stamp_ref(deployment)
                if stamp_ref and stamp_ref != from_ref:
                    raise UpdateError(
                        f"source stamp mismatch: .supabase-version={stamp_ref!r} meta={from_ref!r}",
                        code=EXIT_SAFETY,
                    )

                auth.record_operation_phase(ctx, phase="creating_recovery_backup")
                prior_state = _capture_prior_state(root, slug, mutation_ctx=ctx)

                from sbfleet.backup import _resolve_identity

                id_path = _resolve_identity(identity)
                if id_path is None:
                    raise UpdateError(
                        "pre-update recovery backup requires --identity or SBFLEET_AGE_IDENTITY",
                        code=EXIT_PREREQUISITE,
                    )

                try:
                    locked = _create_backup_locked(
                        ctx,
                        verify=True,
                        identity=id_path,
                        pre_update=True,
                        restore_prior_state=False,
                    )
                except BackupError as exc:
                    raise UpdateError(str(exc), code=getattr(exc, "code", EXIT_SAFETY)) from exc

                backup_id = locked.backup_id
                if locked.verification != VERIFICATION_RECOVERY:
                    raise UpdateError(
                        "fresh pre-update backup is not recovery-verified",
                        code=EXIT_SAFETY,
                    )
                receipt = load_backup_receipt(root, str(meta["id"]), backup_id)
                if not receipt or not is_recovery_verified_receipt(receipt):
                    raise UpdateError(
                        "fresh recovery receipt missing or weak after backup",
                        code=EXIT_SAFETY,
                    )
                if str(receipt.get("project_id") or "") != str(meta["id"]):
                    raise UpdateError("recovery receipt project_id mismatch", code=EXIT_SAFETY)

                auth.record_operation_phase(
                    ctx,
                    phase="entering_maintenance",
                    evidence={
                        "prior_state": prior_state,
                        "backup_id": backup_id,
                        "backup_verification": locked.verification,
                    },
                )
                try:
                    stop_project(root, slug, already_locked=True, manage_journal=False)
                except ProjectError as exc:
                    raise UpdateError(str(exc), code=getattr(exc, "code", EXIT_FAILURE)) from exc

                live_hashes_before = hash_authority_surface(deployment)
                before_env = up.parse_dotenv((deployment / ".env").read_text(encoding="utf-8"))
                before_secrets = {k: before_env.get(k) for k in sorted(up.REQUIRED_ENV_KEYS)}

                auth.record_operation_phase(ctx, phase="preparing_staging")
                staging = root / "staging" / f"update-{ctx.operation_id}"
                if staging.exists():
                    _wipe_update_staging(staging)
                _seed_staging(deployment, staging)
                _place_source_updater(root, staging, from_ref=from_ref, from_sha=from_sha)
                mode = staging.stat().st_mode & 0o777
                if mode & 0o077:
                    raise UpdateError(
                        f"staging permissions too open: {oct(mode)}",
                        code=EXIT_SAFETY,
                    )

                auth.record_operation_phase(
                    ctx,
                    phase="running_official_updater",
                    evidence={
                        "updater": "update.sh",
                        "to_ref": target,
                        "timeout_s": UPDATER_TIMEOUT_S,
                        "live_hashes_before": live_hashes_before,
                    },
                )
                result = run_official_updater(staging, to_ref=target)
                # Never print raw updater output (may contain secrets from .env merge logs).
                redacted = _redact_updater_output(
                    (result.stdout or "") + (result.stderr or ""),
                    before_secrets,
                )
                auth.record_operation_phase(
                    ctx,
                    phase="running_official_updater",
                    evidence={
                        "updater_exit": result.returncode,
                        "updater_timed_out": bool(result.timed_out),
                        "updater_output_redacted_len": len(redacted),
                    },
                )

                auth.record_operation_phase(ctx, phase="validating_staging")
                try:
                    inspect_updater_result(staging, result, to_ref=target, to_sha=to_sha)
                    # Full updater-owned target-surface bind — stronger than
                    # critical-cache digests alone; before stamp/promote/run.sh.
                    bind_staging_to_approved_target(
                        root,
                        staging,
                        to_ref=target,
                        to_sha=to_sha,
                        from_ref=from_ref,
                        from_sha=from_sha,
                    )
                except UpdateError as inspect_exc:
                    # Prove live unchanged on staging failure.
                    after = hash_authority_surface(deployment)
                    if after != live_hashes_before:
                        raise UpdateError(
                            "CRITICAL: live authority surface changed before promotion",
                            code=EXIT_FAILURE,
                        ) from inspect_exc
                    raise

                # Destination-owned env reconcile on staged .env.
                staged_env_path = staging / ".env"
                dest_env_path = deployment / ".env"
                staged_env = up.parse_dotenv(staged_env_path.read_text(encoding="utf-8"))
                dest_env = up.parse_dotenv(dest_env_path.read_text(encoding="utf-8"))
                reconciled = reconcile_update_env(
                    staged_env=staged_env,
                    destination_env=dest_env,
                    destination_meta=meta,
                    before_secrets=before_secrets,
                )
                staged_env_path.write_text(up.dump_dotenv(reconciled), encoding="utf-8")
                os.chmod(staged_env_path, 0o600)

                # Regenerate fleet override into staging (sbfleet-owned).
                override = c.render_override(
                    compose_project=str(meta["compose_project"]),
                    fleet_id=str(meta["fleet_id"]),
                    project_id=str(meta["id"]),
                    gateway_port=int(meta["ports"]["gateway"]),
                    db_direct_port=int(meta["ports"]["db_direct"]),
                    pooler_session_port=int(meta["ports"]["pooler_session"]),
                    pooler_transaction_port=int(meta["ports"]["pooler_transaction"]),
                )
                (staging / "docker-compose.override.yml").write_text(override, encoding="utf-8")
                up.write_version_stamp(staging, ref=target, sha=to_sha)

                if not c.supports_override_tag():
                    raise UpdateError("Compose !override unsupported", code=EXIT_PREREQUISITE)
                # Validate staged compose with dummy private paths — use staging as deployment root.
                cfg = c.compose_config_json(
                    staging,
                    compose_project=str(meta["compose_project"]),
                    env={
                        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                        "COMPOSE_PROJECT_NAME": str(meta["compose_project"]),
                        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
                    },
                )
                c.validate_resolved_config(
                    cfg,
                    compose_project=str(meta["compose_project"]),
                    fleet_id=str(meta["fleet_id"]),
                    project_id=str(meta["id"]),
                    gateway_port=int(meta["ports"]["gateway"]),
                    db_direct_port=int(meta["ports"]["db_direct"]),
                    pooler_session_port=int(meta["ports"]["pooler_session"]),
                    pooler_transaction_port=int(meta["ports"]["pooler_transaction"]),
                    deployment=staging,
                    allowed_bind_roots=[staging, deployment],
                )

                # Re-check live still unchanged before promotion.
                if hash_authority_surface(deployment) != live_hashes_before:
                    raise UpdateError(
                        "live authority surface changed before promotion; aborting",
                        code=EXIT_FAILURE,
                    )

                promote_list = list_promote_relpaths(staging)
                quarantine = root / "staging" / f"update-quarantine-{ctx.operation_id}"
                promote_rec = build_promote_record(
                    operation_id=ctx.operation_id,
                    from_ref=from_ref,
                    from_sha=from_sha,
                    to_ref=target,
                    to_sha=to_sha,
                    backup_id=str(backup_id),
                    staging=staging,
                    deployment=deployment,
                    quarantine=quarantine,
                    relpaths=promote_list,
                )
                promote_rec_path = write_promote_record(staging, promote_rec)
                # Journal summary AFTER canonical record; may lag after process death.
                auth.record_operation_phase(
                    ctx,
                    phase="promoting",
                    evidence={
                        "promote_count": len(promote_list),
                        "promote_record_path": str(promote_rec_path),
                        "quarantine_path": str(quarantine),
                        "backup_id": backup_id,
                        "from_ref": from_ref,
                        "from_sha": from_sha,
                        "to_ref": target,
                        "to_sha": to_sha,
                    },
                )
                promotion_begun = True
                promoted = mechanical_promote(
                    staging,
                    deployment,
                    record=promote_rec,
                    quarantine=quarantine,
                )
                # Optional lagged summary — never the recovery truth.
                auth.record_operation_phase(
                    ctx,
                    phase="promoting",
                    evidence={
                        "promote_verified_count": len(promoted),
                        "paths_promoted_complete": True,
                    },
                )

                meta = dict(reg.read_project(root, slug))
                meta["upstream"] = {"ref": target, "sha": to_sha}
                # last_verified stays old until runtime verification succeeds
                reg.write_project(root, meta)
                set_promote_record_flags(staging, promote_rec, metadata_advanced=True)
                auth.record_operation_phase(
                    ctx,
                    phase="promoting",
                    evidence={"metadata_advanced": True},
                )

                auth.revalidate_deployment_authority(ctx)

                # Pin/vendor proof after promote, before any promoted script (run.sh pull).
                try:
                    up.verify_deployment_vendor(deployment, sha=to_sha, root=root)
                except up.UpstreamError as exc:
                    raise UpdateError(
                        f"post-promote vendor verification failed: {exc}",
                        code=EXIT_SAFETY,
                    ) from exc

                auth.record_operation_phase(ctx, phase="pulling_images")
                env = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "HOME": str(deployment / ".run-home"),
                    "LC_ALL": "C",
                    "COMPOSE_PROJECT_NAME": str(meta["compose_project"]),
                    "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
                }
                (deployment / ".run-home").mkdir(mode=0o700, exist_ok=True)
                pull = run(
                    ["sh", "run.sh", "pull"],
                    cwd=deployment,
                    env=env,
                    timeout=600.0,
                    check=False,
                )
                if not pull.ok:
                    auth.fail_operation(
                        ctx,
                        error="run.sh pull failed",
                        phase="pulling_images",
                        evidence={"backup_id": backup_id, "promotion_begun": True},
                    )
                    print(
                        "error: run.sh pull failed; configuration may be promoted; "
                        f"unresolved UPDATING {ctx.operation_id}; "
                        f"pre-update archive {backup_id} is recovery evidence — "
                        "same-pin restore into a promoted different-pin tree is unsupported; "
                        "use: sbfleet update PROJECT --reconcile --operation-id "
                        f"{ctx.operation_id}; no automatic cross-version rollback",
                        file=sys.stderr,
                    )
                    return EXIT_FAILURE

                auth.record_operation_phase(ctx, phase="starting_for_verification")
                try:
                    start_project(
                        root,
                        slug,
                        timeout=600,
                        already_locked=True,
                        manage_journal=False,
                    )
                except ProjectError as exc:
                    auth.fail_operation(
                        ctx,
                        error=f"start failed: {exc}",
                        phase="starting_for_verification",
                        evidence={"backup_id": backup_id},
                    )
                    try:
                        stop_project(root, slug, already_locked=True, manage_journal=False)
                    except Exception:  # noqa: BLE001
                        pass
                    print(
                        f"error: post-update start failed; unresolved UPDATING {ctx.operation_id}; "
                        f"pre-update archive {backup_id} is recovery evidence — "
                        "same-pin restore into a promoted different-pin tree is unsupported; "
                        f"use update --reconcile --operation-id {ctx.operation_id}; "
                        "no automatic cross-version rollback",
                        file=sys.stderr,
                    )
                    return EXIT_FAILURE

                auth.record_operation_phase(ctx, phase="verifying_runtime")
                healthy = False
                last_lifecycle = "UNKNOWN"
                from sbfleet.health import collect_status_for_mutation

                for _ in range(60):
                    report = collect_status_for_mutation(ctx)
                    last_lifecycle = report.lifecycle
                    if report.lifecycle == HEALTHY:
                        healthy = True
                        break
                    time.sleep(5)
                if not healthy:
                    auth.fail_operation(
                        ctx,
                        error=f"runtime verification failed: lifecycle={last_lifecycle}",
                        phase="verifying_runtime",
                        evidence={"backup_id": backup_id, "lifecycle": last_lifecycle},
                    )
                    try:
                        stop_project(root, slug, already_locked=True, manage_journal=False)
                    except Exception:  # noqa: BLE001
                        pass
                    print(
                        "error: post-update health failed; stack left stopped; "
                        f"unresolved UPDATING operation {ctx.operation_id} remains; "
                        f"pre-update archive {backup_id} is recovery evidence "
                        "(same-pin restore into a promoted different-pin destination "
                        "is unsupported; use update --reconcile --operation-id); "
                        "no automatic cross-version rollback",
                        file=sys.stderr,
                    )
                    return EXIT_FAILURE

                if staging is not None and promote_record_path(staging).is_file():
                    try:
                        promote_rec = load_promote_record(promote_record_path(staging))
                        set_promote_record_flags(staging, promote_rec, runtime_verified=True)
                    except UpdateError:
                        pass
                auth.record_operation_phase(
                    ctx,
                    phase="verifying_runtime",
                    evidence={"runtime_verified": True},
                )
                after_env = up.parse_dotenv((deployment / ".env").read_text(encoding="utf-8"))
                for k, before in before_secrets.items():
                    if before is not None and after_env.get(k) != before:
                        raise UpdateError(
                            f"secret {k} changed after promotion",
                            code=EXIT_SAFETY,
                        )

                meta = reg.read_project(root, slug)
                meta["upstream"] = {"ref": target, "sha": to_sha}
                meta["last_verified_upstream"] = {
                    "ref": target,
                    "sha": to_sha,
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                reg.write_project(root, meta)

                auth.record_operation_phase(
                    ctx,
                    phase="restoring_prior_state",
                    evidence={"prior_state": prior_state},
                )
                restored_prior = prior_state
                if prior_state == STOPPED:
                    try:
                        stop_project(root, slug, already_locked=True, manage_journal=False)
                    except ProjectError as exc:
                        raise UpdateError(
                            f"failed to restore STOPPED prior state: {exc}",
                            code=EXIT_FAILURE,
                        ) from exc
                    restored_prior = STOPPED
                else:
                    restored_prior = HEALTHY

                auth.complete_operation(
                    ctx,
                    phase="completed",
                    intent="UPDATING",
                    evidence={
                        "backup_id": backup_id,
                        "promoted_files": len(promoted),
                        "prior_state": prior_state,
                        "restored_prior_state": restored_prior,
                        "last_verified": meta["last_verified_upstream"],
                    },
                )

                # Wipe plaintext staging after verified success.
                cleanup_residuals: list[str] = []
                if staging is not None:
                    try:
                        _wipe_update_staging(staging)
                        staging = None
                    except Exception as exc:  # noqa: BLE001
                        cleanup_residuals.append(f"{staging}: {exc}"[:240])
                if quarantine is not None and quarantine.exists():
                    try:
                        _wipe_update_staging(quarantine)
                    except Exception as exc:  # noqa: BLE001
                        cleanup_residuals.append(f"{quarantine}: {exc}"[:240])

                payload = {
                    "ok": True,
                    "updated": True,
                    "slug": slug,
                    "from": {"ref": from_ref, "sha": from_sha},
                    "to": {"ref": target, "sha": to_sha},
                    "backup_id": backup_id,
                    "promoted_files": len(promoted),
                    "prior_state": prior_state,
                    "restored_prior_state": restored_prior,
                    "last_verified_upstream": meta["last_verified_upstream"],
                    "cleanup_ok": not cleanup_residuals,
                    "rollback": (
                        f"pre-update archive {backup_id} remains recovery evidence; "
                        "same-pin restore applies only while destination pin still matches "
                        "the archive; after promotion use update --reconcile for the "
                        "unresolved operation — no automatic cross-version rollback"
                    ),
                }
                if cleanup_residuals:
                    payload["cleanup_residuals"] = cleanup_residuals
                    payload["ok"] = False
                print(json.dumps(payload, indent=2, sort_keys=True))
                if cleanup_residuals:
                    print(
                        "error: update applied but plaintext cleanup incomplete; "
                        "residuals: " + "; ".join(cleanup_residuals),
                        file=sys.stderr,
                    )
                    return EXIT_FAILURE
                return EXIT_OK

            except UpdateError as exc:
                evidence: dict[str, Any] = {
                    "backup_id": backup_id,
                    "promotion_begun": promotion_begun,
                    "prior_state": prior_state,
                }
                if staging is not None and staging.exists():
                    evidence["diagnostic_staging"] = str(staging)
                    # Retain private diagnostic staging on failure; ensure perms.
                    try:
                        os.chmod(staging, 0o700)
                    except OSError:
                        pass
                if live_hashes_before and not promotion_begun:
                    evidence["live_hashes_unchanged"] = (
                        hash_authority_surface(deployment) == live_hashes_before
                    )
                auth.fail_operation(ctx, error=str(exc), phase="failed", evidence=evidence)
                _emit_update_error(exc, deployment=deployment)
                if backup_id:
                    hint = (
                        f"recovery: pre-update archive {backup_id} is evidence/data protection; "
                        "ordinary restore/update refuse while UPDATING is unresolved; "
                        f"use update --reconcile --operation-id {ctx.operation_id} "
                        "when a promote-record exists. Same-pin restore into a promoted "
                        "different-pin destination is unsupported; no cross-version rollback."
                    )
                    if not promotion_begun:
                        hint = (
                            f"recovery: promotion did not begin; after explicit reconcile/"
                            f"journal resolution, same-pin restore of {backup_id} may apply "
                            f"while destination pin still matches the archive. "
                            f"Unresolved operation {ctx.operation_id} still blocks ordinary "
                            "restore/update until reconciled."
                        )
                    print(hint, file=sys.stderr)
                return exc.code

    except UpdateError as exc:
        _emit_update_error(exc, deployment=_deployment_for_diag(root, slug))
        return exc.code
    except up.UpstreamError as exc:
        _emit_update_error(exc, deployment=_deployment_for_diag(root, slug))
        return EXIT_SAFETY
    except Exception as exc:  # noqa: BLE001
        _emit_update_error(exc, deployment=_deployment_for_diag(root, slug))
        return EXIT_FAILURE


def _interrupted_recovery_hint(*, operation_id: str, backup_id: str, phase: str) -> str:
    return (
        f"interrupted update phase={phase}; operation_id={operation_id}; "
        f"pre-update archive {backup_id} remains recovery evidence. "
        "Ordinary update/restore/remove refuse while UPDATING is unresolved. "
        "Same-pin restore into a promoted different-pin destination is unsupported. "
        f"Use: sbfleet update PROJECT --reconcile --operation-id {operation_id}. "
        "sbfleet does not claim generic cross-version rollback."
    )


def reconcile_interrupted_update(
    root: Path,
    slug: str,
    *,
    operation_id: str,
    yes: bool,
) -> int:
    """Continue one unresolved UPDATING op from its canonical promote-record.

    Does not create a new backup, rebuild the plan, or change operation identity.
    """
    from sbfleet import authority as auth
    from sbfleet.authority import AuthorityError
    from sbfleet.health import HEALTHY, STOPPED
    from sbfleet.projects import ProjectError, start_project, stop_project

    op_id = operation_id.strip()
    if not op_id:
        print("error: --operation-id required", file=sys.stderr)
        return EXIT_SAFETY

    try:
        with auth.authorize_mutation(
            root,
            slug,
            intent="update",
            ignore_unresolved_journal=True,
            skip_pin_vendor_check=True,
            validate_compose=False,
        ) as ctx:
            journal = reg.read_operation_journal(root, slug) or {}
            if str(journal.get("intent") or "") != "UPDATING":
                print(
                    "error: reconcile requires unresolved UPDATING journal",
                    file=sys.stderr,
                )
                return EXIT_SAFETY
            if not reg.journal_is_unresolved(journal):
                print("error: journal is not unresolved", file=sys.stderr)
                return EXIT_SAFETY
            jid = str(journal.get("operation_id") or "")
            if jid != op_id:
                print(
                    f"error: operation_id mismatch: journal={jid!r} requested={op_id!r}",
                    file=sys.stderr,
                )
                return EXIT_SAFETY
            # Bind to original identity — never replace.
            ctx.operation_id = op_id

            evidence = journal.get("evidence") if isinstance(journal.get("evidence"), dict) else {}
            staging = root / "staging" / f"update-{op_id}"
            rec_path_hint = evidence.get("promote_record_path")
            rec_path = Path(str(rec_path_hint)) if rec_path_hint else promote_record_path(staging)
            if not rec_path.is_file():
                # Fallback to operation-scoped staging location.
                rec_path = promote_record_path(staging)
            if not rec_path.is_file():
                payload = {
                    "ok": False,
                    "reconcile": True,
                    "operation_id": op_id,
                    "mode": "diagnose_only",
                    "reason": "promote_record_missing",
                    "hint": (
                        "canonical promote-record absent; cannot safely resume. "
                        "Manual operator recovery required; do not blind-retry update "
                        "or cross-pin restore."
                    ),
                }
                print(json.dumps(payload, indent=2, sort_keys=True))
                auth.record_operation_phase(
                    ctx,
                    phase="reconcile_diagnose",
                    evidence={"reconcile": "diagnose_only", "reason": "promote_record_missing"},
                )
                return EXIT_SAFETY

            record = load_promote_record(rec_path)
            if str(record.get("operation_id") or "") != op_id:
                print("error: promote-record operation_id mismatch", file=sys.stderr)
                return EXIT_SAFETY

            from_ref = str(record["from_ref"])
            from_sha = str(record["from_sha"])
            to_ref = str(record["to_ref"])
            to_sha = str(record["to_sha"])
            backup_id = str(record.get("backup_id") or evidence.get("backup_id") or "")
            staging = Path(str(record.get("staging_path") or staging))
            quarantine = Path(
                str(
                    record.get("quarantine_path")
                    or (root / "staging" / f"update-quarantine-{op_id}")
                )
            )
            deployment = ctx.deployment

            diagnoses = diagnose_promote_paths(deployment, record)
            phase = promotion_phase_label(record, diagnoses)
            auth.record_operation_phase(
                ctx,
                phase="reconcile_diagnose",
                evidence={
                    "reconcile_phase": phase,
                    "promote_record_path": str(rec_path),
                    "path_classes": {
                        c: sum(1 for d in diagnoses if d["classification"] == c)
                        for c in (
                            CLASS_EXACT_SOURCE,
                            CLASS_EXACT_TARGET,
                            CLASS_MISSING,
                            CLASS_FOREIGN,
                        )
                    },
                },
            )

            foreign = [d for d in diagnoses if d["classification"] == CLASS_FOREIGN]
            if foreign:
                payload = {
                    "ok": False,
                    "reconcile": True,
                    "operation_id": op_id,
                    "mode": "diagnose_only",
                    "phase": phase,
                    "reason": "foreign_or_unexpected_paths",
                    "foreign": [d["rel"] for d in foreign[:20]],
                    "hint": _interrupted_recovery_hint(
                        operation_id=op_id, backup_id=backup_id, phase=phase
                    ),
                }
                print(json.dumps(payload, indent=2, sort_keys=True))
                return EXIT_SAFETY

            # Staging required for any remaining promote mutations.
            need_promote = [
                d for d in diagnoses if d["classification"] in {CLASS_EXACT_SOURCE, CLASS_MISSING}
            ]
            staging_ok = False
            if staging.is_dir() and not staging.is_symlink():
                try:
                    bind_staging_to_approved_target(
                        root,
                        staging,
                        to_ref=to_ref,
                        to_sha=to_sha,
                        from_ref=from_ref,
                        from_sha=from_sha,
                    )
                    staging_ok = True
                except UpdateError as exc:
                    if need_promote:
                        from sbfleet.process import sanitize_configured_diagnostic

                        safe_reason = sanitize_configured_diagnostic(
                            f"staging_rebind_failed: {exc}",
                            deployment=deployment,
                            max_len=500,
                        )
                        payload = {
                            "ok": False,
                            "reconcile": True,
                            "operation_id": op_id,
                            "mode": "diagnose_only",
                            "phase": phase,
                            "reason": safe_reason,
                            "hint": _interrupted_recovery_hint(
                                operation_id=op_id, backup_id=backup_id, phase=phase
                            ),
                        }
                        print(json.dumps(payload, indent=2, sort_keys=True))
                        return EXIT_SAFETY
            elif need_promote:
                payload = {
                    "ok": False,
                    "reconcile": True,
                    "operation_id": op_id,
                    "mode": "diagnose_only",
                    "phase": phase,
                    "reason": "staging_missing_cannot_resume_promotion",
                    "hint": _interrupted_recovery_hint(
                        operation_id=op_id, backup_id=backup_id, phase=phase
                    ),
                }
                print(json.dumps(payload, indent=2, sort_keys=True))
                return EXIT_SAFETY

            if not yes:
                print("error: internal: reconcile requires --yes", file=sys.stderr)
                return EXIT_SAFETY

            # Resume remaining promotions only — never rebuild plan or new backup.
            auth.begin_operation(ctx, phase="reconcile_resume")
            promoted: list[str] = []
            if need_promote:
                assert staging_ok
                # Reload record from disk (canonical).
                record = load_promote_record(promote_record_path(staging))
                remaining_rels = {d["rel"] for d in need_promote}
                # Temporarily shrink paths list for mechanical_promote input copy.
                subset = dict(record)
                subset["paths"] = [
                    dict(p) for p in record["paths"] if p.get("rel") in remaining_rels
                ]
                write_promote_record(staging, record)  # ensure durable before mutate
                for entry in subset["paths"]:
                    rel = str(entry["rel"])
                    # Promote single path via shared helper loop body.
                    src = staging / rel
                    dest = deployment / rel
                    target = entry["target"]
                    update_promote_path_progress(
                        staging, record, rel=rel, progress=PROGRESS_PREPARED
                    )
                    quarantine.mkdir(parents=True, mode=0o700)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if dest.exists() or dest.is_symlink():
                        qdest = quarantine / rel
                        qdest.parent.mkdir(parents=True, exist_ok=True)
                        if dest.is_symlink() or not dest.is_file():
                            raise UpdateError(
                                f"refuse promote over non-file: {rel}",
                                code=EXIT_SAFETY,
                            )
                        try:
                            shutil.copy2(dest, qdest)
                        except PermissionError:
                            _docker_copy_file(dest, qdest)
                    tmp = dest.with_name(dest.name + ".sbfleet-promote-tmp")
                    try:
                        try:
                            shutil.copy2(src, tmp)
                            mode = src.stat().st_mode
                            os.chmod(tmp, stat.S_IMODE(mode))
                            os.replace(tmp, dest)
                        except PermissionError:
                            if tmp.exists():
                                tmp.unlink(missing_ok=True)
                            _docker_copy_file(src, dest)
                    finally:
                        if tmp.exists():
                            try:
                                tmp.unlink(missing_ok=True)
                            except OSError:
                                pass
                    live = observe_path_state(dest)
                    if not path_states_equal(live, target):
                        raise UpdateError(
                            f"reconcile post-promote verify failed for {rel}",
                            code=EXIT_SAFETY,
                        )
                    update_promote_path_progress(
                        staging, record, rel=rel, progress=PROGRESS_VERIFIED
                    )
                    promoted.append(rel)
                set_promote_record_flags(staging, record, paths_promoted_complete=True)
                auth.record_operation_phase(
                    ctx,
                    phase="reconcile_promoted",
                    evidence={"resumed_paths": len(promoted)},
                )

            # Re-diagnose — all must be exact_target before downstream.
            record = load_promote_record(
                promote_record_path(staging) if staging.is_dir() else rec_path
            )
            diagnoses = diagnose_promote_paths(deployment, record)
            if any(d["classification"] != CLASS_EXACT_TARGET for d in diagnoses):
                payload = {
                    "ok": False,
                    "reconcile": True,
                    "operation_id": op_id,
                    "mode": "diagnose_only",
                    "reason": "paths_not_all_target_after_resume",
                    "classes": [d["classification"] for d in diagnoses],
                }
                print(json.dumps(payload, indent=2, sort_keys=True))
                return EXIT_SAFETY

            # Metadata advancement where not already established (frozen plan wins).
            meta = dict(reg.read_project(root, slug))
            cur_up = meta.get("upstream") if isinstance(meta.get("upstream"), dict) else {}
            if str(cur_up.get("ref") or "") != to_ref or str(cur_up.get("sha") or "") != to_sha:
                meta["upstream"] = {"ref": to_ref, "sha": to_sha}
                reg.write_project(root, meta)
            if staging.is_dir():
                set_promote_record_flags(staging, record, metadata_advanced=True)

            auth.revalidate_deployment_authority(ctx)
            try:
                up.verify_deployment_vendor(deployment, sha=to_sha, root=root)
            except up.UpstreamError as exc:
                raise UpdateError(
                    f"post-reconcile vendor verification failed: {exc}",
                    code=EXIT_SAFETY,
                ) from exc

            # Downstream only — no fresh backup / no replan.
            prior_state = STOPPED
            if isinstance(evidence.get("prior_state"), str):
                prior_state = str(evidence["prior_state"])

            auth.record_operation_phase(ctx, phase="pulling_images")
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(deployment / ".run-home"),
                "LC_ALL": "C",
                "COMPOSE_PROJECT_NAME": str(meta["compose_project"]),
                "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
            }
            (deployment / ".run-home").mkdir(mode=0o700, exist_ok=True)
            pull = run(
                ["sh", "run.sh", "pull"],
                cwd=deployment,
                env=env,
                timeout=600.0,
                check=False,
            )
            if not pull.ok:
                auth.fail_operation(
                    ctx,
                    error="run.sh pull failed during reconcile",
                    phase="pulling_images",
                    evidence={"backup_id": backup_id},
                )
                print(
                    _interrupted_recovery_hint(
                        operation_id=op_id, backup_id=backup_id, phase="pull_failed"
                    ),
                    file=sys.stderr,
                )
                return EXIT_FAILURE

            auth.record_operation_phase(ctx, phase="starting_for_verification")
            try:
                start_project(
                    root,
                    slug,
                    timeout=600,
                    already_locked=True,
                    manage_journal=False,
                )
            except ProjectError as exc:
                auth.fail_operation(
                    ctx,
                    error=f"reconcile start failed: {exc}",
                    phase="starting_for_verification",
                    evidence={"backup_id": backup_id},
                )
                try:
                    stop_project(root, slug, already_locked=True, manage_journal=False)
                except Exception:  # noqa: BLE001
                    pass
                print(
                    _interrupted_recovery_hint(
                        operation_id=op_id, backup_id=backup_id, phase="start_failed"
                    ),
                    file=sys.stderr,
                )
                return EXIT_FAILURE

            auth.record_operation_phase(ctx, phase="verifying_runtime")
            healthy = False
            last_lifecycle = "UNKNOWN"
            from sbfleet.health import collect_status_for_mutation

            for _ in range(60):
                report = collect_status_for_mutation(ctx)
                last_lifecycle = report.lifecycle
                if report.lifecycle == HEALTHY:
                    healthy = True
                    break
                time.sleep(5)
            if not healthy:
                auth.fail_operation(
                    ctx,
                    error=f"reconcile runtime verify failed: {last_lifecycle}",
                    phase="verifying_runtime",
                    evidence={"backup_id": backup_id, "lifecycle": last_lifecycle},
                )
                try:
                    stop_project(root, slug, already_locked=True, manage_journal=False)
                except Exception:  # noqa: BLE001
                    pass
                print(
                    _interrupted_recovery_hint(
                        operation_id=op_id, backup_id=backup_id, phase="verify_failed"
                    ),
                    file=sys.stderr,
                )
                return EXIT_FAILURE

            if staging.is_dir():
                set_promote_record_flags(staging, record, runtime_verified=True)

            meta = reg.read_project(root, slug)
            meta["upstream"] = {"ref": to_ref, "sha": to_sha}
            meta["last_verified_upstream"] = {
                "ref": to_ref,
                "sha": to_sha,
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            reg.write_project(root, meta)

            restored_prior = prior_state
            if prior_state == STOPPED:
                try:
                    stop_project(root, slug, already_locked=True, manage_journal=False)
                except ProjectError as exc:
                    raise UpdateError(
                        f"failed to restore STOPPED prior state: {exc}",
                        code=EXIT_FAILURE,
                    ) from exc
                restored_prior = STOPPED
            else:
                restored_prior = HEALTHY

            auth.complete_operation(
                ctx,
                phase="completed",
                intent="UPDATING",
                evidence={
                    "backup_id": backup_id,
                    "reconciled": True,
                    "resumed_paths": len(promoted),
                    "prior_state": prior_state,
                    "restored_prior_state": restored_prior,
                    "last_verified": meta["last_verified_upstream"],
                },
            )

            cleanup_residuals: list[str] = []
            if staging.is_dir():
                try:
                    _wipe_update_staging(staging)
                except Exception as exc:  # noqa: BLE001
                    cleanup_residuals.append(f"{staging}: {exc}"[:240])
            if quarantine.exists():
                try:
                    _wipe_update_staging(quarantine)
                except Exception as exc:  # noqa: BLE001
                    cleanup_residuals.append(f"{quarantine}: {exc}"[:240])

            payload = {
                "ok": not cleanup_residuals,
                "reconcile": True,
                "updated": True,
                "operation_id": op_id,
                "from": {"ref": from_ref, "sha": from_sha},
                "to": {"ref": to_ref, "sha": to_sha},
                "backup_id": backup_id,
                "resumed_paths": len(promoted),
                "restored_prior_state": restored_prior,
                "last_verified_upstream": meta["last_verified_upstream"],
                "cleanup_ok": not cleanup_residuals,
            }
            if cleanup_residuals:
                payload["cleanup_residuals"] = cleanup_residuals
            print(json.dumps(payload, indent=2, sort_keys=True))
            return EXIT_OK if not cleanup_residuals else EXIT_FAILURE

    except UpdateError as exc:
        _emit_update_error(exc, deployment=_deployment_for_diag(root, slug))
        return exc.code
    except AuthorityError as exc:
        _emit_update_error(exc, deployment=_deployment_for_diag(root, slug))
        return getattr(exc, "code", EXIT_SAFETY)
    except Exception as exc:  # noqa: BLE001
        _emit_update_error(exc, deployment=_deployment_for_diag(root, slug))
        return EXIT_FAILURE
