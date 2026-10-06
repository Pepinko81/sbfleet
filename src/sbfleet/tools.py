"""Managed host-tool resolution (age, pinned Supabase CLI).

Normal installs invoke tools by absolute path under the managed software
prefix. PATH fallback is only for unmanaged/development installs.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

PINNED_SUPABASE_CLI = "2.118.0"
PINNED_AGE = "1.3.2"

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


class ToolError(Exception):
    """Managed tool missing or incompatible."""


def allow_path_tools() -> bool:
    """True when PATH fallback is explicitly enabled."""
    return os.environ.get("SBFLEET_ALLOW_PATH_TOOLS", "").strip() not in {"", "0", "false", "False"}


def software_prefix() -> Path | None:
    """Return the managed install prefix (…/sbfleet/current) when present."""
    override = os.environ.get("SBFLEET_SOFTWARE_ROOT", "").strip()
    if override:
        path = Path(override).expanduser()
        return path if path.is_dir() else None

    prefix = Path(sys.prefix).resolve()
    if prefix.name == "venv":
        candidate = prefix.parent
        if (candidate / "install.json").is_file() or (candidate / "tools").is_dir():
            return candidate

    home = os.environ.get("HOME", "").strip()
    if home:
        current = Path(home) / ".local" / "lib" / "sbfleet" / "current"
        if current.is_dir():
            return current
    return None


def managed_supabase_path(prefix: Path | None = None) -> Path | None:
    root = prefix if prefix is not None else software_prefix()
    if root is None:
        return None
    path = root / "tools" / "supabase" / PINNED_SUPABASE_CLI / "supabase"
    return path if path.is_file() and os.access(path, os.X_OK) else None


def managed_age_path(prefix: Path | None = None) -> Path | None:
    root = prefix if prefix is not None else software_prefix()
    if root is None:
        return None
    path = root / "tools" / "age" / PINNED_AGE / "age"
    return path if path.is_file() and os.access(path, os.X_OK) else None


def _is_node_modules(path: Path) -> bool:
    return "node_modules" in path.parts


def _run_version(argv: list[str]) -> str | None:
    from sbfleet.process import run

    result = run(
        argv,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        check=False,
        timeout=5.0,
    )
    text = (result.stdout or result.stderr or "").strip()
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


def _path_candidates(name: str) -> list[Path]:
    found: list[Path] = []
    which = shutil.which(name)
    if which:
        found.append(Path(which))
    # Also scan PATH entries explicitly for first non-node_modules match order.
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        candidate = Path(entry) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            if candidate not in found:
                found.append(candidate)
    return found


def resolve_supabase() -> tuple[str | None, str]:
    """Return (absolute_path_or_none, detail) for the pinned Supabase CLI."""
    managed = managed_supabase_path()
    if managed is not None:
        ver = _run_version([str(managed), "--version"])
        if ver == PINNED_SUPABASE_CLI:
            return str(managed), f"managed {ver}"
        return None, f"managed CLI version {ver or 'unknown'} != {PINNED_SUPABASE_CLI}"

    if software_prefix() is not None and not allow_path_tools():
        return None, f"managed Supabase CLI {PINNED_SUPABASE_CLI} not found"

    if software_prefix() is None or allow_path_tools():
        for candidate in _path_candidates("supabase"):
            if _is_node_modules(candidate):
                continue
            ver = _run_version([str(candidate), "--version"])
            if ver == PINNED_SUPABASE_CLI:
                return str(candidate), f"path {ver}"
            if ver:
                return None, f"CLI {ver} != {PINNED_SUPABASE_CLI}"
        return None, f"Supabase CLI {PINNED_SUPABASE_CLI} not found"
    return None, f"Supabase CLI {PINNED_SUPABASE_CLI} not found"


def resolve_age() -> tuple[str | None, str]:
    """Return (absolute_path_or_none, detail) for managed/pinned age."""
    managed = managed_age_path()
    if managed is not None:
        ver = _run_version([str(managed), "--version"])
        # age prints v1.3.2 — accept matching numeric pin.
        if ver == PINNED_AGE:
            return str(managed), f"managed {ver}"
        # Still accept executable managed binary if version probe odd but file pinned.
        if ver is None:
            return str(managed), "managed (version unparsed)"
        return str(managed), f"managed {ver}"

    if software_prefix() is not None and not allow_path_tools():
        return None, f"managed age {PINNED_AGE} not found"

    if software_prefix() is None or allow_path_tools():
        for candidate in _path_candidates("age"):
            if _is_node_modules(candidate):
                continue
            return str(candidate), "path"
        return None, "age not found"
    return None, "age not found"


def require_supabase() -> str:
    path, detail = resolve_supabase()
    if not path:
        raise ToolError(detail)
    return path


def require_age() -> str:
    path, detail = resolve_age()
    if not path:
        raise ToolError(detail)
    return path


def sandbox_unavailable_reason() -> str | None:
    """Short reason when sandbox CLI is unavailable, else None."""
    path, detail = resolve_supabase()
    if path:
        return None
    if "not found" in detail and "managed" in detail:
        return f"CLI {PINNED_SUPABASE_CLI} not found"
    if "!=" in detail or "version" in detail:
        return detail.replace("managed CLI version ", "CLI ").replace("CLI ", "CLI ", 1)
    if "not found" in detail:
        return f"CLI {PINNED_SUPABASE_CLI} not found"
    return detail
