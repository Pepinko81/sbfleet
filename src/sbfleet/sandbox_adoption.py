"""Sandbox adoption records, uniqueness index, locks (Run 2D)."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbfleet.cli import EXIT_SAFETY
from sbfleet.registry import DEFAULT_LOCK_TIMEOUT_S, FileLock, LockTimeoutError

ADOPTION_SCHEMA_VERSION = 1
JOURNAL_NAME = "authority-journal.json"
ADOPTION_NAME = "adoption.json"


class SandboxAdoptionError(Exception):
    def __init__(self, msg: str, *, code: int = EXIT_SAFETY) -> None:
        super().__init__(msg)
        self.code = code


def path_hash_short(canonical_root: Path) -> str:
    """Readable name helper only — not sole authority."""
    return hashlib.sha256(str(canonical_root).encode("utf-8")).hexdigest()[:16]


def project_id_index_key(cli_project_id: str) -> str:
    """Path-safe deterministic encoding; never interpolate raw project_id."""
    return hashlib.sha256(cli_project_id.encode("utf-8")).hexdigest()


def canonicalize_app_root(path: Path, *, fleet_home: Path | None = None) -> Path:
    if not path.exists():
        raise SandboxAdoptionError(f"sandbox path does not exist: {path}")
    if not path.is_dir():
        raise SandboxAdoptionError(f"sandbox path must be a directory: {path}")
    # Identity = realpath; symlink aliases collapse.
    canonical = path.resolve()
    if not canonical.is_dir():
        raise SandboxAdoptionError(f"canonical sandbox path is not a directory: {canonical}")
    if fleet_home is not None:
        home = fleet_home.resolve()
        for blocked in ("projects", "backups", "cache", "staging", "sandboxes"):
            banned = (home / blocked).resolve()
            try:
                canonical.relative_to(banned)
            except ValueError:
                continue
            raise SandboxAdoptionError(
                f"sandbox path must not be inside fleet {blocked}/: {canonical}"
            )
    return canonical


def sandboxes_root(home: Path) -> Path:
    return home / "sandboxes"


def state_dir_for(home: Path, canonical: Path) -> Path:
    return sandboxes_root(home) / path_hash_short(canonical)


def index_path_for(home: Path, cli_project_id: str) -> Path:
    return sandboxes_root(home) / "index" / "by-project-id" / project_id_index_key(cli_project_id)


def registry_lock_path(home: Path) -> Path:
    return sandboxes_root(home) / "registry.lock"


def sandbox_lock_path(home: Path, canonical: Path) -> Path:
    return state_dir_for(home, canonical) / "sandbox.lock"


@dataclass
class AdoptionRecord:
    schema_version: int
    sandbox_uuid: str
    canonical_app_root: str
    path_hash: str
    cli_project_id: str
    config_fingerprint: str
    fingerprint_fields: dict[str, Any]
    cli_version: str
    migration_mode: str
    network_id: str | None
    network_name: str
    owned_resources: dict[str, Any]
    adopted_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sandbox_uuid": self.sandbox_uuid,
            "canonical_app_root": self.canonical_app_root,
            "path_hash": self.path_hash,
            "cli_project_id": self.cli_project_id,
            "config_fingerprint": self.config_fingerprint,
            "fingerprint_fields": self.fingerprint_fields,
            "cli_version": self.cli_version,
            "migration_mode": self.migration_mode,
            "network_id": self.network_id,
            "network_name": self.network_name,
            "owned_resources": self.owned_resources,
            "adopted_at": self.adopted_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdoptionRecord:
        required = (
            "schema_version",
            "sandbox_uuid",
            "canonical_app_root",
            "path_hash",
            "cli_project_id",
            "config_fingerprint",
            "cli_version",
            "migration_mode",
            "network_name",
            "owned_resources",
            "adopted_at",
            "updated_at",
        )
        for k in required:
            if k not in data:
                raise SandboxAdoptionError(f"adoption missing field: {k}")
        if data["schema_version"] != ADOPTION_SCHEMA_VERSION:
            raise SandboxAdoptionError(
                f"unsupported adoption schema_version: {data['schema_version']}"
            )
        return cls(
            schema_version=int(data["schema_version"]),
            sandbox_uuid=str(data["sandbox_uuid"]),
            canonical_app_root=str(data["canonical_app_root"]),
            path_hash=str(data["path_hash"]),
            cli_project_id=str(data["cli_project_id"]),
            config_fingerprint=str(data["config_fingerprint"]),
            fingerprint_fields=dict(data.get("fingerprint_fields") or {}),
            cli_version=str(data["cli_version"]),
            migration_mode=str(data["migration_mode"]),
            network_id=data.get("network_id"),
            network_name=str(data["network_name"]),
            owned_resources=dict(data["owned_resources"] or {}),
            adopted_at=str(data["adopted_at"]),
            updated_at=str(data["updated_at"]),
        )


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json_atomic(path: Path, data: dict[str, Any], *, mode: int = 0o600) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    os.chmod(parent, 0o700)
    payload = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        # fsync directory best-effort
        try:
            dir_fd = os.open(str(parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SandboxAdoptionError(f"unreadable authority JSON {path}: {exc}") from exc


def index_payload(record: AdoptionRecord) -> dict[str, Any]:
    return {
        "schema_version": ADOPTION_SCHEMA_VERSION,
        "sandbox_uuid": record.sandbox_uuid,
        "canonical_app_root": record.canonical_app_root,
        "path_hash": record.path_hash,
        "cli_project_id": record.cli_project_id,
    }


class SandboxLocks:
    """Acquire registry then per-sandbox lock; no recursive acquisition."""

    def __init__(
        self,
        home: Path,
        canonical: Path,
        *,
        timeout: float = DEFAULT_LOCK_TIMEOUT_S,
    ) -> None:
        self.home = home
        self.canonical = canonical
        self.timeout = timeout
        self._reg: FileLock | None = None
        self._sb: FileLock | None = None

    def __enter__(self) -> SandboxLocks:
        sandboxes_root(self.home).mkdir(parents=True, exist_ok=True)
        os.chmod(sandboxes_root(self.home), 0o700)
        state_dir_for(self.home, self.canonical).mkdir(parents=True, exist_ok=True)
        os.chmod(state_dir_for(self.home, self.canonical), 0o700)
        self._reg = FileLock(registry_lock_path(self.home), timeout=self.timeout)
        try:
            self._reg.acquire()
        except LockTimeoutError as exc:
            self._reg = None
            raise SandboxAdoptionError(f"sandbox registry lock timeout: {exc}") from exc
        # Any second-lock failure must release the registry lock.
        self._sb = FileLock(sandbox_lock_path(self.home, self.canonical), timeout=self.timeout)
        try:
            self._sb.acquire()
        except LockTimeoutError as exc:
            self._reg.release()
            self._reg = None
            self._sb = None
            raise SandboxAdoptionError(f"sandbox lock timeout: {exc}") from exc
        except Exception:
            self._reg.release()
            self._reg = None
            self._sb = None
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        if self._sb is not None:
            self._sb.release()
            self._sb = None
        if self._reg is not None:
            self._reg.release()
            self._reg = None


def journal_path(home: Path) -> Path:
    return sandboxes_root(home) / JOURNAL_NAME


def detect_short_hash_collision(home: Path, canonical: Path, phash: str) -> None:
    """Refuse if another adoption under same short hash has different canonical root."""
    state = sandboxes_root(home) / phash
    adoption_file = state / ADOPTION_NAME
    if not adoption_file.is_file():
        return
    data = _read_json(adoption_file)
    existing = data.get("canonical_app_root")
    if existing and Path(existing).resolve() != canonical.resolve():
        raise SandboxAdoptionError(
            f"short path_hash collision: {phash} already binds {existing!r}, not {str(canonical)!r}"
        )


def reconcile_adoption_index(
    home: Path,
    canonical: Path,
    *,
    cli_project_id: str | None = None,
) -> AdoptionRecord | None:
    """
    Fail closed on inconsistent adoption↔index pair or interrupted journal.
    Returns existing adoption for this canonical root if consistent, else None if absent.
    """
    jpath = journal_path(home)
    if jpath.exists():
        raise SandboxAdoptionError(
            "interrupted sandbox authority journal present; refuse mutation until resolved "
            f"({jpath})"
        )

    phash = path_hash_short(canonical)
    detect_short_hash_collision(home, canonical, phash)
    state = state_dir_for(home, canonical)
    adoption_file = state / ADOPTION_NAME

    # Scan index for this project id if provided, and for any index pointing at this path_hash.
    index_dir = sandboxes_root(home) / "index" / "by-project-id"
    adoption: AdoptionRecord | None = None
    if adoption_file.is_file():
        adoption = AdoptionRecord.from_dict(_read_json(adoption_file))
        if Path(adoption.canonical_app_root).resolve() != canonical.resolve():
            raise SandboxAdoptionError(
                "adoption canonical_app_root mismatch for state dir "
                f"{phash}: {adoption.canonical_app_root!r} vs {str(canonical)!r}"
            )
        if adoption.path_hash != phash:
            raise SandboxAdoptionError("adoption path_hash does not match state directory name")

        idx = index_path_for(home, adoption.cli_project_id)
        if not idx.is_file():
            raise SandboxAdoptionError(
                f"adoption exists but project-id index missing for {adoption.cli_project_id!r}"
            )
        idx_data = _read_json(idx)
        for field in ("sandbox_uuid", "canonical_app_root", "cli_project_id", "path_hash"):
            if idx_data.get(field) != getattr(adoption, field):
                raise SandboxAdoptionError(
                    f"adoption/index disagree on {field}: "
                    f"adoption={getattr(adoption, field)!r} index={idx_data.get(field)!r}"
                )
        if cli_project_id and adoption.cli_project_id != cli_project_id:
            # Project ID is immutable after adoption. Caller must refuse;
            # do not treat this as a soft revalidate hint.
            raise SandboxAdoptionError(
                f"adopted project_id {adoption.cli_project_id!r} differs from config "
                f"{cli_project_id!r}; project ID is immutable after adoption — "
                "destroy and re-adopt (or create a new sandbox identity), not --revalidate"
            )
        return adoption

    # No adoption for this root: ensure no orphan index claims this project id for another root,
    # and no orphan index claims this path_hash.
    if cli_project_id:
        idx = index_path_for(home, cli_project_id)
        if idx.is_file():
            idx_data = _read_json(idx)
            other_root = idx_data.get("canonical_app_root")
            if other_root and Path(str(other_root)).resolve() != canonical.resolve():
                raise SandboxAdoptionError(
                    f"cli project_id {cli_project_id!r} already adopted by {other_root!r}"
                )
            # Index without matching adoption
            raise SandboxAdoptionError(
                f"project-id index exists but adoption missing for {cli_project_id!r}"
            )

    if index_dir.is_dir():
        for p in index_dir.iterdir():
            if not p.is_file():
                continue
            try:
                idx_data = _read_json(p)
            except SandboxAdoptionError:
                raise
            if idx_data.get("path_hash") == phash:
                raise SandboxAdoptionError(
                    f"orphan project-id index {p.name} points at path_hash {phash} "
                    "without local adoption"
                )
            # Index without adoption file for claimed path_hash
            claimed_hash = idx_data.get("path_hash")
            if claimed_hash:
                claimed_adoption = sandboxes_root(home) / str(claimed_hash) / ADOPTION_NAME
                if not claimed_adoption.is_file():
                    raise SandboxAdoptionError(
                        f"index {p.name} exists but adoption missing at {claimed_adoption}"
                    )

    return None


def new_adoption(
    *,
    canonical: Path,
    cli_project_id: str,
    config_fingerprint: str,
    fingerprint_fields: dict[str, Any],
    cli_version: str,
    migration_mode: str,
    network_id: str | None = None,
    owned_resources: dict[str, Any] | None = None,
) -> AdoptionRecord:
    phash = path_hash_short(canonical)
    now = _now()
    return AdoptionRecord(
        schema_version=ADOPTION_SCHEMA_VERSION,
        sandbox_uuid=str(uuid.uuid4()),
        canonical_app_root=str(canonical),
        path_hash=phash,
        cli_project_id=cli_project_id,
        config_fingerprint=config_fingerprint,
        fingerprint_fields=dict(fingerprint_fields),
        cli_version=cli_version,
        migration_mode=migration_mode,
        network_id=network_id,
        network_name=f"sbfleet-sb-{phash}",
        owned_resources=dict(owned_resources or {}),
        adopted_at=now,
        updated_at=now,
    )


def commit_adoption_pair(home: Path, record: AdoptionRecord) -> None:
    """
    Crash-consistent write of adoption + index under caller-held registry lock.

    Order: write journal → write both temps → rename index then adoption → clear journal.
    """
    state = state_dir_for(home, Path(record.canonical_app_root))
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    adoption_file = state / ADOPTION_NAME
    idx = index_path_for(home, record.cli_project_id)
    idx.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(idx.parent, 0o700)

    jpath = journal_path(home)
    journal = {
        "phase": "commit",
        "sandbox_uuid": record.sandbox_uuid,
        "cli_project_id": record.cli_project_id,
        "path_hash": record.path_hash,
        "adoption_path": str(adoption_file),
        "index_path": str(idx),
    }
    _write_json_atomic(jpath, journal)

    try:
        _write_json_atomic(idx, index_payload(record))
        _write_json_atomic(adoption_file, record.to_dict())
    except Exception:
        # Leave journal for fail-closed detection
        raise

    try:
        jpath.unlink()
    except OSError as exc:
        raise SandboxAdoptionError(f"failed to clear authority journal: {exc}") from exc


def clear_owned_resources(record: AdoptionRecord) -> AdoptionRecord:
    data = record.to_dict()
    data["owned_resources"] = {}
    data["network_id"] = None
    data["updated_at"] = _now()
    return AdoptionRecord.from_dict(data)


def update_record_fields(record: AdoptionRecord, **kwargs: Any) -> AdoptionRecord:
    data = record.to_dict()
    data.update(kwargs)
    data["updated_at"] = _now()
    return AdoptionRecord.from_dict(data)
