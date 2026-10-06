"""Sandbox config TOML parsing, fingerprint, locality, migration-mode (sandbox adoption)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, unquote, urlparse

from sbfleet.cli import EXIT_PREREQUISITE, EXIT_SAFETY

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]


class SandboxConfigError(Exception):
    def __init__(self, msg: str, *, code: int = EXIT_SAFETY) -> None:
        super().__init__(msg)
        self.code = code


ALLOWED_PROJECT_PREFIXES = ("sbfleet-dev-", "sbfleet-test-", "sbfleet-sb-")
MIGRATION_MODES = frozenset({"supabase", "external"})

# Authority-relevant fingerprint field paths (dotted).
FINGERPRINT_KEYS = (
    "project_id",
    "api.port",
    "db.port",
    "db.major_version",
    "db.migrations.enabled",
    "db.migrations.schema_paths",
    "db.seed.enabled",
    "db.seed.sql_paths",
    "db.pooler.enabled",
    "db.pooler.port",
    "studio.port",
    "studio.api_url",
    "studio.openai_api_url",
    "experimental",
    "remotes",
)

# Pinned CLI 2.118.0 local status DB_URL is authority-host form with no query string
# (postgresql://user:pass@127.0.0.1:PORT/postgres). Smallest allowlist: empty.
# Any query parameter (including target-changing host/hostaddr/port/service/servicefile)
# is refused by sandbox authority.
POSTGRES_URI_ALLOWED_QUERY_PARAMS: frozenset[str] = frozenset()

EndpointKind = Literal["http", "postgres", "auto"]


@dataclass(frozen=True)
class ParsedSandboxConfig:
    raw: dict[str, Any]
    project_id: str
    fingerprint: str
    fingerprint_fields: dict[str, Any]
    api_port: int | None
    db_port: int | None
    studio_port: int | None
    migrations_enabled: bool
    seed_enabled: bool
    has_remotes: bool


def _dig(data: dict[str, Any], path: str) -> Any:
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def load_toml(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise SandboxConfigError(f"refusing symlinked config.toml: {path}")
    if not path.is_file():
        raise SandboxConfigError(
            "missing supabase/config.toml — run `supabase init` in the app repo first",
            code=EXIT_PREREQUISITE,
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SandboxConfigError(f"cannot read config.toml: {exc}") from exc
    try:
        data = tomllib.loads(text)
    except Exception as exc:  # tomllib.TOMLDecodeError / tomli equivalent
        raise SandboxConfigError(f"malformed config.toml: {exc}", code=EXIT_PREREQUISITE) from exc
    if not isinstance(data, dict):
        raise SandboxConfigError("config.toml root must be a table", code=EXIT_PREREQUISITE)
    return data


def _require_project_id(data: dict[str, Any]) -> str:
    if "project_id" not in data:
        raise SandboxConfigError("config.toml missing project_id", code=EXIT_PREREQUISITE)
    pid = data["project_id"]
    if not isinstance(pid, str) or not pid.strip():
        raise SandboxConfigError(
            "config.toml project_id must be a non-empty string", code=EXIT_PREREQUISITE
        )
    if not any(pid.startswith(p) for p in ALLOWED_PROJECT_PREFIXES):
        raise SandboxConfigError(
            f"project_id {pid!r} must start with sbfleet-dev-/sbfleet-test-/sbfleet-sb-",
        )
    return pid


def _collect_fingerprint_fields(data: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in FINGERPRINT_KEYS:
        if "." not in key:
            if key in data:
                fields[key] = data[key]
            continue
        val = _dig(data, key)
        if val is not None:
            fields[key] = val
    # External / escape-prone path settings if present
    for path_key in (
        "db.migrations.schema_paths",
        "db.seed.sql_paths",
        "functions",
        "edge_runtime.policy",
    ):
        val = _dig(data, path_key) if "." in path_key else data.get(path_key)
        if val is not None and path_key not in fields:
            fields[path_key] = val
    return fields


def fingerprint_fields(data: dict[str, Any]) -> dict[str, Any]:
    return _collect_fingerprint_fields(data)


def compute_fingerprint(fields: dict[str, Any]) -> str:
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def classify_fingerprint_drift(
    adopted_fields: dict[str, Any] | None,
    current_fields: dict[str, Any],
) -> list[str]:
    """Return human-readable authority field drift lines."""
    old = adopted_fields or {}
    keys = sorted(set(old) | set(current_fields))
    lines: list[str] = []
    for k in keys:
        a = old.get(k, "<absent>")
        b = current_fields.get(k, "<absent>")
        if a != b:
            lines.append(f"{k}: {a!r} -> {b!r}")
    return lines


def _as_port(val: Any, name: str) -> int | None:
    if val is None:
        return None
    if isinstance(val, bool) or not isinstance(val, int):
        raise SandboxConfigError(f"{name} must be an integer port", code=EXIT_PREREQUISITE)
    if not (1 <= val <= 65535):
        raise SandboxConfigError(f"{name} out of range: {val}", code=EXIT_PREREQUISITE)
    return val


def parse_sandbox_config(app: Path) -> ParsedSandboxConfig:
    cfg_path = app / "supabase" / "config.toml"
    data = load_toml(cfg_path)
    project_id = _require_project_id(data)
    if "remotes" in data and data["remotes"] not in (None, {}, []):
        # Presence of remotes table with content is linked/remote evidence at config layer.
        has_remotes = True
    else:
        has_remotes = False
    fields = _collect_fingerprint_fields(data)
    fp = compute_fingerprint(fields)
    api = data.get("api") if isinstance(data.get("api"), dict) else {}
    db = data.get("db") if isinstance(data.get("db"), dict) else {}
    studio = data.get("studio") if isinstance(data.get("studio"), dict) else {}
    mig = db.get("migrations") if isinstance(db.get("migrations"), dict) else {}
    seed = db.get("seed") if isinstance(db.get("seed"), dict) else {}
    migrations_enabled = bool(mig.get("enabled", True)) if mig else True
    seed_enabled = bool(seed.get("enabled", True)) if seed else True
    return ParsedSandboxConfig(
        raw=data,
        project_id=project_id,
        fingerprint=fp,
        fingerprint_fields=fields,
        api_port=_as_port(api.get("port"), "api.port"),
        db_port=_as_port(db.get("port"), "db.port"),
        studio_port=_as_port(studio.get("port"), "studio.port"),
        migrations_enabled=migrations_enabled,
        seed_enabled=seed_enabled,
        has_remotes=has_remotes,
    )


def _path_contained(app_r: Path, raw: str, *, require_exists: bool) -> None:
    p = Path(raw)
    try:
        if p.is_absolute():
            resolved = p.resolve(strict=False)
        else:
            resolved = (app_r / p).resolve(strict=False)
    except OSError as exc:
        raise SandboxConfigError(f"unresolvable config path: {raw}") from exc
    if app_r not in resolved.parents and resolved != app_r:
        raise SandboxConfigError(f"config path escapes app root: {raw}")
    # Symlink escape: if the path exists, resolve through links and re-check.
    try:
        if resolved.exists() or p.exists():
            final = (
                resolved.resolve(strict=True)
                if resolved.exists()
                else (app_r / p).resolve(strict=True)
            )
            if app_r not in final.parents and final != app_r:
                raise SandboxConfigError(f"config path symlink escapes app root: {raw}")
            return
    except OSError as exc:
        raise SandboxConfigError(f"unresolvable config path: {raw}") from exc
    if require_exists:
        raise SandboxConfigError(f"authority-relevant config path missing: {raw}")


def _collect_function_paths(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (role, path) for CLI-loaded function entrypoints/import maps."""
    out: list[tuple[str, str]] = []
    functions = data.get("functions")
    if isinstance(functions, dict):
        for name, body in functions.items():
            if not isinstance(body, dict):
                continue
            for key in ("entrypoint", "import_map", "static_files"):
                val = body.get(key)
                if isinstance(val, str) and val.strip():
                    out.append((f"functions.{name}.{key}", val.strip()))
                elif isinstance(val, list):
                    for i, item in enumerate(val):
                        if isinstance(item, str) and item.strip():
                            out.append((f"functions.{name}.{key}[{i}]", item.strip()))
    return out


def validate_external_paths(app: Path, data: dict[str, Any]) -> None:
    """Refuse config paths that escape the app tree (migrations, seed, functions)."""
    app_r = app.resolve()
    candidates: list[tuple[str, str, bool]] = []
    db = data.get("db") if isinstance(data.get("db"), dict) else {}
    mig = db.get("migrations") if isinstance(db.get("migrations"), dict) else {}
    seed = db.get("seed") if isinstance(db.get("seed"), dict) else {}
    for key in ("schema_paths",):
        v = mig.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    candidates.append((f"db.migrations.{key}", item.strip(), False))
        elif isinstance(v, str) and v.strip():
            candidates.append((f"db.migrations.{key}", v.strip(), False))
    for key in ("sql_paths",):
        v = seed.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    candidates.append((f"db.seed.{key}", item.strip(), False))
        elif isinstance(v, str) and v.strip():
            candidates.append((f"db.seed.{key}", v.strip(), False))
    for role, path in _collect_function_paths(data):
        # Function entrypoint/import_map are authority-relevant when declared.
        candidates.append((role, path, True))
    for _role, raw, require_exists in candidates:
        _path_contained(app_r, raw, require_exists=require_exists)


def static_binding_preflight(cfg: ParsedSandboxConfig) -> None:
    """Reject statically knowable unsafe/public host-bind configuration."""
    studio = cfg.raw.get("studio") if isinstance(cfg.raw.get("studio"), dict) else {}
    for key in ("api_url", "openai_api_url"):
        url = studio.get(key)
        if isinstance(url, str) and url.strip():
            assert_local_url(url, context=f"studio.{key}", kind="http")

    # Refuse explicit public bind addresses in known address-like keys only.
    # Do not scan the whole document: default config uses allowed_cidrs=["0.0.0.0/0"].
    suspicious_keys = {
        "address",
        "bind",
        "host",
        "listen",
        "hostname",
        "api_url",
        "db_url",
        "openai_api_url",
    }

    def _walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = f"{path}.{k}" if path else str(k)
                kl = str(k).lower()
                if kl in suspicious_keys and isinstance(v, str):
                    if v.strip() in {"0.0.0.0", "::", "[::]"} or v.strip().startswith("0.0.0.0:"):
                        raise SandboxConfigError(f"config {p} requests public bind {v!r}; refusing")
                    if "://" in v:
                        kind: EndpointKind = (
                            "postgres" if kl == "db_url" else "http" if "url" in kl else "auto"
                        )
                        assert_local_url(v, context=p, kind=kind)
                _walk(v, p)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _walk(v, f"{path}[{i}]")

    _walk(cfg.raw)


def validate_migration_mode(cfg: ParsedSandboxConfig, mode: str) -> None:
    if mode not in MIGRATION_MODES:
        raise SandboxConfigError(f"unsupported migration-mode: {mode!r}", code=EXIT_PREREQUISITE)
    if mode == "external":
        if cfg.migrations_enabled:
            raise SandboxConfigError(
                "external migration-mode requires [db.migrations] enabled = false"
            )
        if cfg.seed_enabled:
            raise SandboxConfigError("external migration-mode requires [db.seed] enabled = false")
        # Application migration SQL files may exist; do not require empty directories.


LOOPBACK_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "[::1]",
    }
)


def is_loopback_host(host: str | None) -> bool:
    if host is None or host == "":
        return False
    h = host.strip().lower()
    # Strip brackets for IPv6 literals
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h in {"localhost", "127.0.0.1", "::1"}:
        return True
    # Reject prefix tricks: localhost.example.com, 127.0.0.1.example.com
    if h.startswith("localhost.") or h.startswith("127.0.0.1."):
        return False
    try:
        ip = ipaddress.ip_address(h)
        return bool(ip.is_loopback)
    except ValueError:
        return False


def _parse_postgres_query(query: str, *, context: str) -> list[tuple[str, str]]:
    """Decode query pairs; refuse malformed encoding and duplicate keys."""
    if not query:
        return []
    # Reject bare malformed percent sequences before parse_qsl soft-handling.
    i = 0
    while i < len(query):
        if query[i] == "%":
            hexpart = query[i + 1 : i + 3]
            if len(hexpart) < 2 or any(c not in "0123456789abcdefABCDEF" for c in hexpart):
                raise SandboxConfigError(f"{context}: malformed query percent-encoding")
            i += 3
            continue
        i += 1
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise SandboxConfigError(f"{context}: malformed query string: {exc}") from exc
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for raw_k, raw_v in pairs:
        try:
            key = unquote(raw_k, errors="strict").lower()
            val = unquote(raw_v, errors="strict")
        except UnicodeDecodeError as exc:
            raise SandboxConfigError(f"{context}: malformed query encoding") from exc
        if key in seen:
            raise SandboxConfigError(f"{context}: duplicate query parameter {key!r}")
        seen.add(key)
        out.append((key, val))
    return out


def assert_local_url(
    url: str,
    *,
    context: str = "url",
    kind: EndpointKind = "auto",
) -> str:
    if not isinstance(url, str) or not url.strip():
        raise SandboxConfigError(f"{context}: empty URL", code=EXIT_SAFETY)
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    scheme = (parsed.scheme or "").lower()

    resolved_kind: EndpointKind
    if kind == "auto":
        if scheme in {"postgresql", "postgres"}:
            resolved_kind = "postgres"
        elif scheme in {"http", "https"}:
            resolved_kind = "http"
        else:
            raise SandboxConfigError(f"{context}: unsupported URL scheme {scheme!r}")
    else:
        resolved_kind = kind

    if resolved_kind == "http":
        if scheme not in {"http", "https"}:
            raise SandboxConfigError(
                f"{context}: HTTP endpoint refuses scheme {scheme!r}",
            )
        # Reject userinfo on HTTP/API/Studio URLs (credential-bearing / spoof surface).
        if (
            parsed.username is not None
            or parsed.password is not None
            or "@" in (parsed.netloc or "")
        ):
            raise SandboxConfigError(f"{context}: refusing HTTP URL with userinfo")
        host = parsed.hostname
        if not is_loopback_host(host):
            raise SandboxConfigError(
                f"{context}: refusing non-loopback host {host!r} in {url!r}",
            )
        return cleaned

    # PostgreSQL
    if scheme not in {"postgresql", "postgres"}:
        raise SandboxConfigError(
            f"{context}: PostgreSQL endpoint refuses scheme {scheme!r}",
        )
    host = parsed.hostname
    if not is_loopback_host(host):
        raise SandboxConfigError(
            f"{context}: refusing non-loopback host {host!r} in {url!r}",
        )
    # Allowlist query params (empty for CLI 2.118.0 normal local DB_URL).
    # Explicitly reject target-changing forms even if allowlist later grows.
    forbidden_target_keys = frozenset({"host", "hostaddr", "port", "service", "servicefile"})
    pairs = _parse_postgres_query(parsed.query, context=context)
    for key, _val in pairs:
        if key in forbidden_target_keys:
            raise SandboxConfigError(
                f"{context}: refusing PostgreSQL query target override {key!r}",
            )
        if key not in POSTGRES_URI_ALLOWED_QUERY_PARAMS:
            raise SandboxConfigError(
                f"{context}: unsupported PostgreSQL query parameter {key!r}",
            )
    return cleaned


def assert_loopback_host_ip(host_ip: str, *, context: str = "HostIp") -> None:
    if host_ip in {"", "0.0.0.0", "::"}:
        # Empty HostIp is ambiguous on some engines — refuse unless proven elsewhere.
        raise SandboxConfigError(f"{context}: refusing ambiguous/public HostIp {host_ip!r}")
    if not is_loopback_host(host_ip):
        raise SandboxConfigError(f"{context}: refusing non-loopback HostIp {host_ip!r}")
