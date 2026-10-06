"""Filesystem registry, identity, atomic metadata and advisory locks."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FORMAT_VERSION = 1
MAX_JSON_BYTES = 1_048_576
SLUG_RE = re.compile(r"^(?:[a-z]|[a-z][a-z0-9-]{0,30}[a-z0-9])$")
RESERVED_SLUGS = frozenset({"all"})
DEFAULT_LOCK_TIMEOUT_S = 30.0
DEFAULT_PORT_RANGE = (20000, 39999)

# Operation journal states for mutation authority .
OP_STATE_PLANNED = "planned"
OP_STATE_IN_PROGRESS = "in_progress"
OP_STATE_FAILED = "failed"
OP_STATE_INTERRUPTED = "interrupted"
OP_STATE_COMPLETED = "completed"
OP_STATES = frozenset(
    {
        OP_STATE_PLANNED,
        OP_STATE_IN_PROGRESS,
        OP_STATE_FAILED,
        OP_STATE_INTERRUPTED,
        OP_STATE_COMPLETED,
    }
)
# Intents that block ordinary start when unresolved.
UNRESOLVED_BLOCKING_INTENTS = frozenset(
    {
        "BACKUP",
        "RESTORING",
        "UPDATING",
        "REMOVING",
        "STARTING",
        "STOPPING",
        "RESTARTING",
        "CREATING",
    }
)


class RegistryError(Exception):
    """Base registry error."""


class NotFoundError(RegistryError):
    """Managed project directory truly absent (exit 3)."""


class ValidationError(RegistryError):
    """Invalid identity or metadata."""


class LockTimeoutError(RegistryError):
    """Could not acquire flock within timeout."""


class OwnershipError(RegistryError):
    """Root or entry ownership/safety failure."""


def validate_slug(slug: str) -> str:
    if not isinstance(slug, str):
        raise ValidationError("slug must be a string")
    if slug != slug.strip() or any(ch.isspace() for ch in slug):
        raise ValidationError("slug must not contain whitespace")
    if slug.startswith("-") or "/" in slug or "\\" in slug or ".." in slug:
        raise ValidationError("slug path/option characters rejected")
    if slug.startswith("--") or slug.startswith("-"):
        raise ValidationError("slug must not look like an option")
    try:
        slug.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValidationError("slug must be ASCII") from exc
    if slug in RESERVED_SLUGS:
        raise ValidationError(f"slug '{slug}' is reserved")
    if len(slug) > 32 or not SLUG_RE.fullmatch(slug):
        raise ValidationError(
            "slug must match [a-z][a-z0-9-]{0,30}[a-z0-9] or a single letter (max 32)"
        )
    return slug


def validate_display_name(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 100:
        raise ValidationError("display_name must be 1–100 characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise ValidationError("display_name must not contain control characters")
    return name


def resolve_home(
    explicit: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    env = environ if environ is not None else os.environ
    if explicit is not None:
        raw = str(explicit)
        if not os.path.isabs(raw):
            raise ValidationError("--home must be an absolute path")
        path = Path(raw)
    elif env.get("SBFLEET_HOME"):
        path = Path(env["SBFLEET_HOME"])
        if not path.is_absolute():
            raise ValidationError("SBFLEET_HOME must be absolute")
    elif env.get("XDG_DATA_HOME"):
        path = Path(env["XDG_DATA_HOME"]) / "sbfleet"
    else:
        home = env.get("HOME")
        if not home:
            raise ValidationError("HOME is unset and no fleet root was provided")
        path = Path(home) / ".local" / "share" / "sbfleet"
    return path.resolve(strict=False)


def _check_mode_bits(path: Path, *, expect_dir: bool) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise OwnershipError(f"refusing symlink: {path}")
    if expect_dir and not stat.S_ISDIR(st.st_mode):
        raise OwnershipError(f"expected directory: {path}")
    if not expect_dir and not stat.S_ISREG(st.st_mode):
        raise OwnershipError(f"expected regular file: {path}")
    if st.st_uid != os.getuid():
        raise OwnershipError(f"not owned by current user: {path}")
    if st.st_mode & stat.S_IWOTH:
        raise OwnershipError(f"world-writable path refused: {path}")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _unescape_mount_field(value: str) -> str:
    """Decode octal escapes used in /proc/*/mountinfo path fields."""
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 3 < len(value):
            try:
                out.append(chr(int(value[i + 1 : i + 4], 8)))
                i += 4
                continue
            except ValueError:
                pass
        out.append(value[i])
        i += 1
    return "".join(out)


def _mountinfo_points() -> set[Path] | None:
    """
    Authoritative mount points from /proc/self/mountinfo.
    Returns None when mount table cannot be read or interpreted — callers must fail closed.
    Supported model: Linux local filesystem with readable /proc/self/mountinfo.

    Requires structural validity of the supported Linux mountinfo format:
    ``ID parent major:minor root mountpoint options [optional...] - fstype source superopts``.
    """
    try:
        text = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    except OSError:
        return None
    mounts: set[Path] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        # Minimum: 6 fixed fields before optional/separator, then "-", fstype, source, super.
        # Practical floor before separator search: ID parent maj:min root mnt opts (≥6 tokens)
        # plus "-" and three trailing fields (≥10). Fail closed on short/malformed lines.
        if len(parts) < 10:
            return None
        try:
            int(parts[0])
            int(parts[1])
        except ValueError:
            return None
        if ":" not in parts[2]:
            return None
        # Separator between optional fields and fstype/source/super options.
        try:
            sep = parts.index("-", 6)
        except ValueError:
            return None
        if sep + 3 >= len(parts):
            return None
        raw_mnt = _unescape_mount_field(parts[4])
        if not raw_mnt or not raw_mnt.startswith("/"):
            return None
        try:
            mounts.add(Path(raw_mnt).resolve(strict=False))
        except OSError:
            return None
    return mounts


def _assert_no_unexpected_mount(
    resolved: Path,
    *,
    under: Path,
) -> None:
    """
    Fail closed for authority-sensitive paths: require a readable mount table and
    refuse any mountpoint strictly inside `under` on the path to `resolved`
    (including resolved itself when it is a mountpoint other than `under`).
    """
    mounts = _mountinfo_points()
    if mounts is None:
        raise OwnershipError(
            f"cannot establish mountpoint authority (unreadable or malformed "
            f"/proc/self/mountinfo) for {resolved}; refusing mutation"
        )
    cur = resolved
    while True:
        if cur in mounts and cur != under:
            raise OwnershipError(f"refusing mountpoint in managed path: {cur}")
        if cur == under or cur == cur.parent:
            break
        cur = cur.parent
    # Supplemental check: kernel st_dev heuristic (cannot alone prove absence).
    if os.path.ismount(resolved) and resolved != under:
        raise OwnershipError(f"refusing managed path on mountpoint: {resolved}")


def assert_destructive_tree_safe(root: Path, *, under: Path | None = None) -> Path:
    """
    Before recursively destroying a managed tree, prove mount authority for the
    entire subtree: readable/parseable mountinfo, no unexpected ancestor mounts,
    and no mountpoint at or strictly beneath the destructive root.

    Does not auto-unmount. Does not recurse into contents beyond mountinfo.
    """
    resolved = Path(root).resolve(strict=False)
    under_res = (under if under is not None else resolved).resolve(strict=False)
    mounts = _mountinfo_points()
    if mounts is None:
        raise OwnershipError(
            f"cannot establish mountpoint authority (unreadable or malformed "
            f"/proc/self/mountinfo) for destructive tree {resolved}; refusing deletion"
        )
    if not _is_relative_to(resolved, under_res) and resolved != under_res:
        raise OwnershipError(
            f"destructive root escapes managed under: {resolved} not under {under_res}"
        )
    _assert_no_unexpected_mount(resolved, under=under_res)
    for mnt in mounts:
        if mnt == resolved:
            if resolved != under_res:
                raise OwnershipError(f"refusing destructive root that is a mountpoint: {resolved}")
            continue
        if _is_relative_to(mnt, resolved):
            raise OwnershipError(
                f"refusing destructive tree with nested mountpoint {mnt} under {resolved}"
            )
    return resolved


def safe_rmtree(path: Path, *, under: Path | None = None) -> Path:
    """
    Single checked recursive-deletion boundary.

    Mount/ownership UNKNOWN or refusal is terminal: callers must not catch this and
    retry with shutil.rmtree, ignore_errors, or an unchecked helper.
    Does not auto-unmount or chmod around refusal.
    """
    target = Path(path)
    if not target.exists() and not target.is_symlink():
        return target
    resolved = assert_destructive_tree_safe(target, under=under)
    shutil.rmtree(resolved)
    return resolved


def assert_secret_file(path: Path) -> Path:
    """
    Validate an sbfleet-managed or explicitly authority-sensitive host file.

    Enforces: regular file, current-user owner, nlink==1, mode & 0o077 == 0,
    no symlink follow. Refuses with an actionable error; never chmods.

    Scope: project .env, metadata, locks (via FileLock), managed secret/config,
    and explicitly supplied recovery identity files — not container-owned PGDATA.
    """
    raw = Path(path)
    try:
        st = raw.lstat()
    except FileNotFoundError as exc:
        raise OwnershipError(f"secret/managed file missing: {raw}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise OwnershipError(f"refusing symlink secret/managed file: {raw}")
    if not stat.S_ISREG(st.st_mode):
        raise OwnershipError(f"secret/managed path is not a regular file: {raw}")
    if st.st_uid != os.getuid():
        raise OwnershipError(f"secret/managed file not owned by current user: {raw}")
    if st.st_nlink != 1:
        raise OwnershipError(
            f"refusing hardlinked secret/managed file (nlink={st.st_nlink}): {raw}"
        )
    if st.st_mode & 0o077:
        raise OwnershipError(
            f"secret/managed file must be mode 0600 or stricter "
            f"(got {oct(st.st_mode & 0o777)}); refusing without chmod: {raw}"
        )
    return raw.resolve(strict=False)


def assert_managed_entry(
    path: Path,
    *,
    under: Path,
    expect_dir: bool = False,
    expect_file: bool = False,
    allow_absent: bool = False,
    refuse_mountpoint: bool = False,
    require_owner: bool = True,
) -> Path:
    """
    Narrow filesystem ownership/path validation.
    Uses lstat (no-follow). Does not recurse or chmod runtime data.
    When refuse_mountpoint=True, mount authority is established via
    /proc/self/mountinfo and unknown mount tables fail closed.
    When require_owner=False, only containment/symlink/mode checks apply
    (used for container-owned runtime bind mounts such as PGDATA).
    """
    if expect_dir and expect_file:
        raise ValidationError("expect_dir and expect_file are mutually exclusive")
    under_res = under.resolve(strict=False)
    raw = Path(path)
    if raw.exists() or raw.is_symlink():
        st = raw.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise OwnershipError(f"refusing symlink: {raw}")
        # Resolve without following a final symlink (already refused).
        resolved = raw.resolve(strict=False)
    else:
        if not allow_absent:
            raise OwnershipError(f"path missing: {raw}")
        resolved = raw.resolve(strict=False)
        if not _is_relative_to(resolved, under_res):
            raise OwnershipError(f"path escapes managed root: {raw} not under {under_res}")
        if refuse_mountpoint:
            # Path need not exist; mount table still decides if any component is a mount.
            _assert_no_unexpected_mount(resolved, under=under_res)
        return resolved

    if not _is_relative_to(resolved, under_res):
        raise OwnershipError(f"path escapes managed root: {raw} not under {under_res}")
    if expect_dir and not stat.S_ISDIR(st.st_mode):
        raise OwnershipError(f"expected directory: {raw}")
    if expect_file and not stat.S_ISREG(st.st_mode):
        raise OwnershipError(f"expected regular file: {raw}")
    if require_owner and st.st_uid != os.getuid():
        raise OwnershipError(f"not owned by current user: {raw}")
    if st.st_mode & stat.S_IWOTH:
        raise OwnershipError(f"world-writable path refused: {raw}")
    if refuse_mountpoint:
        _assert_no_unexpected_mount(resolved, under=under_res)
    return resolved


def ensure_root(root: Path) -> Path:
    """
    Initialize fleet root. Directory scaffolding for locks happens first;
    fleet identity creation is serialized under the registry lock.
    """
    root = root.resolve(strict=False)
    if root.exists():
        _check_mode_bits(root, expect_dir=True)
    else:
        root.mkdir(mode=0o700, parents=True)
        os.chmod(root, 0o700)
    locks = root / "locks"
    if not locks.exists():
        locks.mkdir(mode=0o700)
        os.chmod(locks, 0o700)
    else:
        _check_mode_bits(locks, expect_dir=True)

    with registry_lock(root):
        for name in ("projects", "backups", "cache", "staging", "sandboxes"):
            d = root / name
            if not d.exists():
                d.mkdir(mode=0o700)
                os.chmod(d, 0o700)
            else:
                _check_mode_bits(d, expect_dir=True)
        fleet_path = root / "fleet.json"
        if not fleet_path.exists():
            data = {
                "format_version": FORMAT_VERSION,
                "fleet_id": str(uuid.uuid4()),
                "age_recipients": [],
            }
            atomic_write_json(fleet_path, data, mode=0o600)
        else:
            _check_mode_bits(fleet_path, expect_dir=False)
            load_json(fleet_path)
    return root


def atomic_write_json(path: Path, data: Mapping[str, Any], *, mode: int = 0o600) -> None:
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    encoded = payload.encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise ValidationError("JSON payload exceeds size limit")
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        dir_fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def load_json(path: Path) -> dict[str, Any]:
    path = Path(path)
    _check_mode_bits(path, expect_dir=False)
    st = path.stat()
    if st.st_size > MAX_JSON_BYTES:
        raise ValidationError(f"JSON too large: {path}")
    with path.open("r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"malformed JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"JSON root must be an object: {path}")
    version = data.get("format_version")
    if version != FORMAT_VERSION:
        raise ValidationError(f"unsupported format_version {version!r} in {path}")
    return data


def compose_project_name(fleet_id: str, project_id: str) -> str:
    f12 = uuid.UUID(fleet_id).hex[:12]
    p12 = uuid.UUID(project_id).hex[:12]
    return f"sbfleet-{f12}-{p12}"


def fleet_id(root: Path) -> str:
    data = load_json(root / "fleet.json")
    fid = data.get("fleet_id")
    if not isinstance(fid, str):
        raise ValidationError("fleet.json missing fleet_id")
    uuid.UUID(fid)
    return fid


@dataclass(frozen=True)
class ProjectRecord:
    path: Path
    data: dict[str, Any]
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def slug(self) -> str | None:
        slug = self.data.get("slug")
        return slug if isinstance(slug, str) else None


def project_dir(root: Path, slug: str) -> Path:
    validate_slug(slug)
    return root / "projects" / slug


def project_json_path(root: Path, slug: str) -> Path:
    return project_dir(root, slug) / "project.json"


def write_project(root: Path, data: Mapping[str, Any]) -> Path:
    slug = validate_slug(str(data["slug"]))
    validate_display_name(str(data["display_name"]))
    if data.get("format_version") != FORMAT_VERSION:
        raise ValidationError("project format_version must be 1")
    dest_dir = project_dir(root, slug)
    if dest_dir.exists():
        _check_mode_bits(dest_dir, expect_dir=True)
        if dest_dir.is_symlink():
            raise OwnershipError(f"refusing symlinked project: {dest_dir}")
    else:
        dest_dir.mkdir(mode=0o700)
        os.chmod(dest_dir, 0o700)
    path = dest_dir / "project.json"
    atomic_write_json(path, data, mode=0o600)
    return path


def read_project(root: Path, slug: str) -> dict[str, Any]:
    """Load managed project metadata.

    True absence (no ``projects/<slug>/`` tree) raises ``NotFoundError`` (exit 3).
    Directory present but ``project.json`` missing/unreadable as managed identity
    is corrupt/incomplete (``OwnershipError`` / ``ValidationError``) — not exit 3.
    """
    pdir = project_dir(root, slug)
    path = pdir / "project.json"
    if path.is_symlink() or pdir.is_symlink():
        raise OwnershipError(f"refusing symlink project path: {path}")
    if not pdir.exists():
        raise NotFoundError(f"project not found: {slug}")
    if not path.exists():
        raise OwnershipError(f"incomplete/corrupt project '{slug}': project.json missing")
    data = load_json(path)
    if data.get("slug") != slug:
        raise ValidationError(f"slug mismatch in {path}")
    fid = fleet_id(root)
    if data.get("fleet_id") != fid:
        raise OwnershipError(f"fleet_id mismatch for project {slug}")
    return data


def validate_project_identity(root: Path, data: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute and verify project identity relationships (fail closed)."""
    payload = dict(data)
    pid = payload.get("id")
    fid = payload.get("fleet_id")
    if not isinstance(pid, str):
        raise ValidationError("project id missing")
    if not isinstance(fid, str):
        raise ValidationError("fleet_id missing")
    try:
        uuid.UUID(pid)
        uuid.UUID(fid)
    except ValueError as exc:
        raise ValidationError("project id / fleet_id must be UUIDs") from exc
    root_fid = fleet_id(root)
    if fid != root_fid:
        raise OwnershipError("fleet_id does not match fleet.json")
    expected_cp = compose_project_name(fid, pid)
    stored_cp = payload.get("compose_project")
    if stored_cp != expected_cp:
        raise OwnershipError(
            f"compose_project mismatch: metadata={stored_cp!r} expected={expected_cp!r}"
        )
    slug = payload.get("slug")
    if not isinstance(slug, str):
        raise ValidationError("slug missing")
    validate_slug(slug)
    if payload.get("profile") not in (None, "standard"):
        raise ValidationError(f"unsupported profile: {payload.get('profile')!r}")
    ports = payload.get("ports")
    if not isinstance(ports, dict):
        raise ValidationError("ports missing")
    required_ports = ("gateway", "db_direct", "pooler_session", "pooler_transaction")
    values: list[int] = []
    for key in required_ports:
        val = ports.get(key)
        if not isinstance(val, int) or not (1 <= val <= 65535):
            raise ValidationError(f"ports.{key} must be an integer port")
        values.append(val)
    if len(set(values)) != 4:
        raise ValidationError("ports must be four distinct integers")
    upstream = payload.get("upstream")
    if not isinstance(upstream, dict):
        raise ValidationError("upstream missing")
    ref = upstream.get("ref")
    sha = upstream.get("sha")
    if not isinstance(ref, str) or not ref:
        raise ValidationError("upstream.ref missing")
    if not isinstance(sha, str) or len(sha) != 40:
        raise ValidationError("upstream.sha must be 40-char commit")
    return payload


def list_projects(root: Path) -> list[ProjectRecord]:
    projects = root / "projects"
    if not projects.exists():
        return []
    _check_mode_bits(projects, expect_dir=True)
    records: list[ProjectRecord] = []
    for child in sorted(projects.iterdir(), key=lambda p: p.name):
        if child.is_symlink():
            records.append(
                ProjectRecord(
                    path=child,
                    data={"slug": child.name},
                    error="symlinked project refused",
                )
            )
            continue
        if not child.is_dir():
            records.append(
                ProjectRecord(path=child, data={"slug": child.name}, error="not a directory")
            )
            continue
        meta = child / "project.json"
        if not meta.exists():
            records.append(
                ProjectRecord(path=child, data={"slug": child.name}, error="missing project.json")
            )
            continue
        try:
            data = read_project(root, child.name)
            records.append(ProjectRecord(path=child, data=data))
        except RegistryError as exc:
            # Preserve visibility of malformed rows without deleting them.
            partial: dict[str, Any] = {"slug": child.name}
            try:
                raw = json.loads(meta.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    partial = raw
            except (OSError, json.JSONDecodeError):
                pass
            records.append(ProjectRecord(path=child, data=partial, error=str(exc)))
    return records


def write_operation_journal(root: Path, slug: str, journal: Mapping[str, Any]) -> Path:
    dest = project_dir(root, slug) / "operation.json"
    payload = dict(journal)
    payload.setdefault("format_version", FORMAT_VERSION)
    atomic_write_json(dest, payload, mode=0o600)
    return dest


def read_operation_journal(root: Path, slug: str) -> dict[str, Any] | None:
    path = project_dir(root, slug) / "operation.json"
    if not path.exists():
        return None
    return load_json(path)


def new_operation_journal(
    *,
    intent: str,
    phase: str,
    state: str = OP_STATE_IN_PROGRESS,
    operation_id: str | None = None,
    error: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a journal payload with required mutation-authority fields."""
    if state not in OP_STATES:
        raise ValidationError(f"invalid operation state: {state!r}")
    from datetime import datetime, timezone

    payload: dict[str, Any] = {
        "format_version": FORMAT_VERSION,
        "operation_id": operation_id or str(uuid.uuid4()),
        "intent": intent,
        "phase": phase,
        "state": state,
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if error is not None:
        payload["error"] = error
    if extra:
        for key, value in extra.items():
            if key not in payload:
                payload[key] = value
    return payload


def journal_blocks_ordinary_start(journal: Mapping[str, Any] | None) -> bool:
    """Ordinary start must refuse unresolved maintenance/destructive/failed ops."""
    if not journal:
        return False
    state = str(journal.get("state") or "")
    intent = str(journal.get("intent") or "")
    phase = str(journal.get("phase") or "")
    if state == OP_STATE_COMPLETED or phase == "done":
        return False
    if state in {OP_STATE_PLANNED, OP_STATE_IN_PROGRESS, OP_STATE_FAILED, OP_STATE_INTERRUPTED}:
        return True
    if intent in {"UPDATING", "RESTORING", "REMOVING", "BACKUP"} and phase not in {"done", ""}:
        return True
    if phase in {"failed", "interrupted"}:
        return True
    return False


def journal_is_unresolved(journal: Mapping[str, Any] | None) -> bool:
    """Alias for status/doctor: unresolved mutation needing reconciliation."""
    return journal_blocks_ordinary_start(journal)


class FileLock:
    """Advisory flock wrapper; lock files are never unlinked on unlock."""

    def __init__(self, path: Path, *, timeout: float = DEFAULT_LOCK_TIMEOUT_S) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self._fd: int | None = None

    def _open_flags(self, *, create_excl: bool) -> int:
        if not hasattr(os, "O_NOFOLLOW"):
            raise OwnershipError("O_NOFOLLOW unsupported; refusing lock open")
        flags = os.O_RDWR | os.O_NOFOLLOW
        if create_excl:
            flags |= os.O_CREAT | os.O_EXCL
        return flags

    def _assert_lock_path_safe(self) -> None:
        try:
            st = self.path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise OwnershipError(f"refusing symlink lock file: {self.path}")
        if not stat.S_ISREG(st.st_mode):
            raise OwnershipError(f"lock path is not a regular file: {self.path}")
        if st.st_uid != os.getuid():
            raise OwnershipError(f"lock file not owned by current user: {self.path}")
        if st.st_nlink != 1:
            raise OwnershipError(
                f"refusing hardlinked lock file (nlink={st.st_nlink}): {self.path}"
            )

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._assert_lock_path_safe()
        if not self.path.exists():
            try:
                fd = os.open(str(self.path), self._open_flags(create_excl=True), 0o600)
                os.close(fd)
                os.chmod(self.path, 0o600)
            except FileExistsError:
                pass
            except OSError as exc:
                if exc.errno in (errno.EEXIST,):
                    pass
                elif exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)):
                    raise OwnershipError(f"unsafe lock path: {self.path}") from exc
                else:
                    # Race: path appeared; fall through to validate + open.
                    pass
        self._assert_lock_path_safe()
        try:
            self._fd = os.open(str(self.path), self._open_flags(create_excl=False))
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EPERM, errno.ENOENT):
                raise OwnershipError(
                    f"refusing to follow/open unsafe lock path: {self.path}"
                ) from exc
            raise
        # Validate the opened descriptor itself before any truncate/write.
        try:
            st = os.fstat(self._fd)
        except OSError as exc:
            self.release()
            raise OwnershipError(f"cannot fstat lock descriptor: {self.path}") from exc
        if not stat.S_ISREG(st.st_mode):
            self.release()
            raise OwnershipError(f"lock descriptor is not a regular file: {self.path}")
        if st.st_uid != os.getuid():
            self.release()
            raise OwnershipError(f"lock descriptor not owned by current user: {self.path}")
        if st.st_nlink != 1:
            self.release()
            raise OwnershipError(
                f"refusing hardlinked lock file (nlink={st.st_nlink}): {self.path}"
            )
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Truncate only after proving we hold a no-follow regular file fd
                # with nlink==1 (hardlink sentinel cannot be truncated).
                os.ftruncate(self._fd, 0)
                os.lseek(self._fd, 0, os.SEEK_SET)
                info = f"pid={os.getpid()} at={time.time():.0f}\n"
                os.write(self._fd, info.encode("ascii"))
                return
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    self.release()
                    raise
                if time.monotonic() >= deadline:
                    self.release()
                    raise LockTimeoutError(f"timeout acquiring {self.path}") from exc
                time.sleep(0.05)

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None
        # Intentionally do not unlink the lock file.

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def registry_lock(root: Path, *, timeout: float = DEFAULT_LOCK_TIMEOUT_S) -> FileLock:
    return FileLock(root / "locks" / "registry.lock", timeout=timeout)


def project_lock(
    root: Path, project_id: str, *, timeout: float = DEFAULT_LOCK_TIMEOUT_S
) -> FileLock:
    uuid.UUID(project_id)
    return FileLock(root / "locks" / f"{project_id}.lock", timeout=timeout)


@contextmanager
def locked_registry_then_project(
    root: Path,
    project_id: str,
    *,
    timeout: float = DEFAULT_LOCK_TIMEOUT_S,
) -> Iterator[tuple[FileLock, FileLock]]:
    """Acquire registry lock before project lock; never reverse."""
    reg = registry_lock(root, timeout=timeout)
    proj = project_lock(root, project_id, timeout=timeout)
    reg.acquire()
    try:
        proj.acquire()
        try:
            yield reg, proj
        finally:
            proj.release()
    finally:
        reg.release()


def port_range_from_env(environ: Mapping[str, str] | None = None) -> tuple[int, int]:
    env = environ if environ is not None else os.environ
    raw = env.get("SBFLEET_PORT_RANGE", "")
    if not raw:
        return DEFAULT_PORT_RANGE
    if "-" not in raw:
        raise ValidationError("SBFLEET_PORT_RANGE must be START-END")
    a, b = raw.split("-", 1)
    start, end = int(a), int(b)
    if not (1024 <= start < end <= 65535):
        raise ValidationError("port range must be unprivileged and start < end")
    return start, end


def reserved_ports(root: Path) -> set[int]:
    used: set[int] = set()
    for row in list_projects(root):
        ports = row.data.get("ports")
        if isinstance(ports, dict):
            for key in ("gateway", "db_direct", "pooler_session", "pooler_transaction"):
                val = ports.get(key)
                if isinstance(val, int):
                    used.add(val)
                elif isinstance(val, str) and val.isdigit():
                    used.add(int(val))
    return used


def _probe_bind(port: int) -> bool:
    """Return True if 127.0.0.1:port can be bound exclusively right now."""
    import socket

    for family, addr in (
        (socket.AF_INET, ("127.0.0.1", port)),
        (socket.AF_INET6, ("::1", port, 0, 0)),
    ):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            continue
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            if family == socket.AF_INET6:
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                except OSError:
                    pass
            sock.bind(addr)
        except OSError:
            return False
        finally:
            sock.close()
    # Also refuse if wildcard 0.0.0.0 is occupied (dual-stack leak).
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("0.0.0.0", port))
        sock.close()
    except OSError:
        return False
    return True


def docker_published_ports() -> set[int]:
    """Best-effort inventory of host ports published by local Docker."""
    from sbfleet.process import run

    result = run(
        ["docker", "ps", "-q"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=30.0,
        check=False,
    )
    if not result.ok or not result.stdout.strip():
        return set()
    ids = result.stdout.split()
    published: set[int] = set()
    for cid in ids:
        insp = run(
            ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", cid],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=30.0,
            check=False,
        )
        if not insp.ok:
            continue
        try:
            ports = json.loads(insp.stdout or "null")
        except json.JSONDecodeError:
            continue
        if not isinstance(ports, dict):
            continue
        for bindings in ports.values():
            if not bindings:
                continue
            for binding in bindings:
                hp = binding.get("HostPort")
                if hp and str(hp).isdigit():
                    published.add(int(hp))
    return published


def allocate_ports(
    root: Path,
    *,
    port_range: tuple[int, int] | None = None,
    hold_sockets: bool = True,
) -> tuple[dict[str, int], list[Any]]:
    """
    Allocate four distinct loopback ports under caller-held registry lock.
    Returns (ports dict, held socket objects). Caller must close sockets after
    persisting reservation (unavoidable external race documented in NETWORK_AND_PORTS).
    """
    import socket

    start, end = port_range or port_range_from_env()
    used = reserved_ports(root) | docker_published_ports()
    names = ("gateway", "db_direct", "pooler_session", "pooler_transaction")
    chosen: dict[str, int] = {}
    held: list[Any] = []
    candidate = start
    while len(chosen) < 4 and candidate <= end:
        if candidate not in used and _probe_bind(candidate):
            if hold_sockets:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                try:
                    sock.bind(("127.0.0.1", candidate))
                except OSError:
                    sock.close()
                    candidate += 1
                    continue
                held.append(sock)
            name = names[len(chosen)]
            chosen[name] = candidate
            used.add(candidate)
        candidate += 1
    if len(chosen) < 4:
        for sock in held:
            sock.close()
        raise ValidationError(
            f"port range {start}-{end} exhausted or occupied; "
            f"free loopback ports or widen SBFLEET_PORT_RANGE"
        )
    return chosen, held


def release_held_sockets(sockets: list[Any]) -> None:
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass
