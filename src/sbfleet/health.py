"""Health probes and status derivation."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.compose import STANDARD_SERVICES
from sbfleet.process import run, sanitize_configured_diagnostic

if TYPE_CHECKING:
    from sbfleet.authority import MutationContext

HEALTHY = "HEALTHY"
STARTING = "STARTING"
UNHEALTHY = "UNHEALTHY"
STOPPED = "STOPPED"
DEGRADED = "DEGRADED"
UNKNOWN = "UNKNOWN"
FAILED = "FAILED"


@dataclass
class ProbeResult:
    name: str
    status: str
    detail: str = ""


@dataclass
class StatusReport:
    slug: str
    lifecycle: str
    probes: list[ProbeResult] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    enum_ok: bool = True

    @property
    def ok(self) -> bool:
        return self.lifecycle == HEALTHY


@dataclass
class ContainerInspectResult:
    """Result of Docker/Compose container enumeration."""

    ok: bool
    containers: dict[str, dict[str, Any]] = field(default_factory=dict)
    error: str = ""


def lifecycle_op_succeeded(report: StatusReport, *, expect: str) -> bool:
    """Central lifecycle success contract shared by CLI/shell/restore callers."""
    if expect == HEALTHY:
        return report.lifecycle == HEALTHY
    if expect == STOPPED:
        return report.enum_ok and report.lifecycle == STOPPED
    return False


def _basic_auth_header(user: str, password: str) -> str:
    import base64

    token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    return f"Basic {token}"


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when host/scheme stay on the original origin; bound hops."""

    def __init__(self, *, max_hops: int = 3) -> None:
        super().__init__()
        self._max_hops = max_hops
        self._hops = 0
        self._origin: tuple[str, str] | None = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        self._hops += 1
        if self._hops > self._max_hops:
            raise urllib.error.HTTPError(newurl, code, "too many redirects", headers, fp)
        parsed_new = urlparse(newurl)
        if self._origin is None:
            parsed_old = urlparse(req.full_url)
            self._origin = (parsed_old.scheme, parsed_old.netloc)
        if (parsed_new.scheme, parsed_new.netloc) != self._origin:
            raise urllib.error.HTTPError(newurl, code, "off-origin redirect refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def inspect_containers_result(deployment: Path, compose_project: str) -> ContainerInspectResult:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(deployment / ".run-home"),
        "COMPOSE_PROJECT_NAME": compose_project,
        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
        "COMPOSE_PATH_SEPARATOR": ":",
    }
    (deployment / ".run-home").mkdir(mode=0o700, exist_ok=True)
    result = run(
        ["docker", "compose", "ps", "--format", "json"],
        cwd=deployment,
        env=env,
        timeout=60.0,
        check=False,
    )
    if not result.ok:
        detail = sanitize_configured_diagnostic(
            result.stderr or result.stdout or f"rc={result.returncode}",
            deployment=deployment,
            max_len=200,
        )
        return ContainerInspectResult(ok=False, containers={}, error=detail)
    out: dict[str, dict[str, Any]] = {}
    text = (result.stdout or "").strip()
    if not text:
        # Confirmed empty inventory (Compose succeeded) — legitimate STOPPED candidate.
        return ContainerInspectResult(ok=True, containers={})
    rows: list[Any] = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            rows = [data]
        else:
            return ContainerInspectResult(
                ok=False, containers={}, error="compose ps JSON root must be object or array"
            )
    except json.JSONDecodeError:
        # NDJSON: every non-empty line must parse; any malformed line fails closed.
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                return ContainerInspectResult(
                    ok=False,
                    containers={},
                    error=f"malformed compose ps JSON line: {exc}",
                )
    for row in rows:
        if not isinstance(row, dict):
            return ContainerInspectResult(
                ok=False, containers={}, error="compose ps row is not an object"
            )
        service = row.get("Service") or row.get("Name") or ""
        state = row.get("State")
        if service in (None, "") and not row.get("Name"):
            return ContainerInspectResult(
                ok=False, containers={}, error="compose ps row missing Service/Name"
            )
        if state is None and row.get("Health") is None and not row.get("Status"):
            # Require at least one meaningful runtime field for matched services.
            return ContainerInspectResult(
                ok=False, containers={}, error=f"compose ps row missing State for {service!r}"
            )
        matched = False
        for svc in STANDARD_SERVICES:
            if service == svc or str(row.get("Name", "")).endswith(f"-{svc}"):
                out[svc] = row
                matched = True
                break
        if not matched and service:
            # Unknown service row in project enumeration — fail closed rather than skip.
            return ContainerInspectResult(
                ok=False,
                containers={},
                error=f"unexpected compose service row: {service!r}",
            )
    return ContainerInspectResult(ok=True, containers=out)


def inspect_containers(deployment: Path, compose_project: str) -> dict[str, dict[str, Any]]:
    """Backward-compatible wrapper: returns containers only (empty on enum failure)."""
    return inspect_containers_result(deployment, compose_project).containers


def _http_probe(
    url: str,
    *,
    name: str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    expect_status: set[int] | None = None,
    allow_redirects: bool = True,
) -> ProbeResult:
    label = name or url
    expect_status = expect_status or {200}
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    handlers: list[urllib.request.BaseHandler] = []
    if allow_redirects:
        handlers.append(_SameOriginRedirectHandler(max_hops=3))
    else:

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
                return None

        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — loopback only
            code = getattr(resp, "status", 200)
            if code in expect_status:
                return ProbeResult(label, HEALTHY, f"HTTP {code}")
            return ProbeResult(label, UNHEALTHY, f"HTTP {code}")
    except urllib.error.HTTPError as exc:
        if exc.code in expect_status:
            return ProbeResult(label, HEALTHY, f"HTTP {exc.code}")
        return ProbeResult(label, UNHEALTHY, f"HTTP {exc.code}")
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(label, UNHEALTHY, type(exc).__name__)


def _container_probe(svc: str, row: dict[str, Any]) -> ProbeResult:
    health_field = row.get("Health")
    state_field = row.get("State") or ""
    health = str(health_field if health_field not in (None, "") else state_field).lower()
    # Mandatory: starting must never fold into HEALTHY via UNKNOWN.
    if "unhealthy" in health:
        return ProbeResult(svc, UNHEALTHY, health)
    if "starting" in health:
        return ProbeResult(svc, STARTING, health)
    if health_field is not None and str(health_field).lower() == "starting":
        return ProbeResult(svc, STARTING, str(health_field))
    if "healthy" in health or health == "running":
        return ProbeResult(svc, HEALTHY, health or "running")
    if health in {"", "created", "restarting", "paused", "exited", "dead"}:
        if health in {"exited", "dead"}:
            return ProbeResult(svc, UNHEALTHY, health)
        if health == "restarting":
            return ProbeResult(svc, STARTING, health)
        return ProbeResult(svc, UNKNOWN, health or "empty")
    return ProbeResult(svc, UNKNOWN, health)


def _sql_readiness(
    deployment: Path, compose_project: str, containers: dict[str, dict[str, Any]]
) -> ProbeResult:
    if "db" not in containers:
        return ProbeResult("sql", UNHEALTHY, "db container missing")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(deployment / ".run-home"),
        "COMPOSE_PROJECT_NAME": compose_project,
        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
        "COMPOSE_PATH_SEPARATOR": ":",
    }
    result = run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-c",
            "SELECT 1",
        ],
        cwd=deployment,
        env=env,
        timeout=30.0,
        check=False,
    )
    if result.ok and "1" in (result.stdout or ""):
        return ProbeResult("sql", HEALTHY, "SELECT 1")
    detail = sanitize_configured_diagnostic(
        result.stderr or result.stdout or f"rc={result.returncode}",
        deployment=deployment,
        max_len=120,
    )
    return ProbeResult("sql", UNHEALTHY, detail or "sql probe failed")


def _project_locations(root: Path, slug: str, meta: dict[str, Any]) -> dict[str, Any]:
    pdir = reg.project_dir(root, slug)
    deployment = pdir / "deployment"
    nginx_path = pdir / "generated" / "nginx.conf"
    backup_dir = root / "backups" / str(meta.get("id", ""))
    journal = pdir / "operation.json"
    last_backup_id = meta.get("last_backup_id")
    backup_verification = meta.get("last_backup_verification")
    if last_backup_id and not backup_verification:
        from sbfleet.backup import load_backup_receipt, normalize_receipt_verification

        receipt = load_backup_receipt(root, str(meta.get("id", "")), str(last_backup_id))
        backup_verification = (
            normalize_receipt_verification(receipt) if receipt else "missing_receipt"
        )
    ports = meta.get("ports") or {}
    gateway = ports.get("gateway")
    local_studio = f"http://127.0.0.1:{gateway}/project/default" if gateway else None
    public = str(meta.get("public_url") or "").rstrip("/")
    public_studio = f"{public}/project/default" if public else None
    upstream = meta.get("upstream") or {}
    last_verified = meta.get("last_verified_upstream") or {}
    return {
        "project_root": str(pdir),
        "deployment": str(deployment),
        "env_path": str(deployment / ".env"),
        "metadata_path": str(pdir / "project.json"),
        "journal_path": str(journal),
        "backup_dir": str(backup_dir),
        "nginx_path": str(nginx_path) if nginx_path.is_file() else None,
        "nginx_present": nginx_path.is_file(),
        "local_studio_url": local_studio,
        "public_studio_url": public_studio,
        "ports": ports,
        "upstream_ref": upstream.get("ref"),
        "upstream_sha": upstream.get("sha"),
        "last_verified_upstream_ref": last_verified.get("ref"),
        "last_verified_upstream_sha": last_verified.get("sha"),
        "last_backup_id": last_backup_id,
        "backup_verification": backup_verification or "none",
        "image_digests": meta.get("image_digests") or {},
    }


def collect_status(root: Path, slug: str) -> StatusReport:
    """Ordinary project status — never suppresses unresolved maintenance journals."""
    return _collect_status(root, slug, mutation_ctx=None)


def collect_status_for_mutation(mutation_ctx: MutationContext) -> StatusReport:
    """
    Nested runtime verification for a lock-owning MutationContext.

    May ignore the journal only when ``mutation_ctx.operation_id`` matches the
    durable in-progress maintenance journal. A raw operation-id string alone is
    not accepted. Ordinary CLI/status/doctor must use ``collect_status`` only.
    """
    return _collect_status(mutation_ctx.root, mutation_ctx.slug, mutation_ctx=mutation_ctx)


def _collect_status(
    root: Path,
    slug: str,
    *,
    mutation_ctx: MutationContext | None,
) -> StatusReport:
    meta = reg.read_project(root, slug)
    deployment = reg.project_dir(root, slug) / "deployment"
    journal = reg.read_operation_journal(root, slug) or {}
    inspected = inspect_containers_result(deployment, str(meta["compose_project"]))
    probes: list[ProbeResult] = []

    # Unresolved maintenance (including durable in_progress after process death)
    # dominates ordinary runtime truth. Only a lock-owning MutationContext whose
    # operation_id matches the journal may observe subordinate runtime probes
    # without forcing FAILED.
    unresolved = False
    if reg.journal_is_unresolved(journal):
        intent = str(journal.get("intent") or "")
        jid = str(journal.get("operation_id") or "")
        if intent in {"RESTORING", "UPDATING", "REMOVING", "BACKUP"}:
            if mutation_ctx is not None and jid and mutation_ctx.operation_id == jid:
                unresolved = False
            else:
                unresolved = True
    if unresolved:
        intent = str(journal.get("intent") or "")
        phase = str(journal.get("phase") or "")
        state = str(journal.get("state") or "")
        probes.append(
            ProbeResult(
                "operation",
                FAILED,
                f"unresolved {intent}/{phase}/{state or 'legacy'}",
            )
        )

    if not inspected.ok:
        probes.append(ProbeResult("docker-compose", UNKNOWN, inspected.error or "enum failed"))
        lifecycle = FAILED if unresolved else UNKNOWN
        intent = str(journal.get("intent") or "")
        phase = str(journal.get("phase") or "")
        if not unresolved:
            if intent in {"UPDATING", "RESTORING", "STARTING", "CREATING"} and phase in {
                "failed",
                "interrupted",
            }:
                lifecycle = FAILED
            elif intent in {"CREATING", "STARTING"} and not meta.get("creation_complete"):
                lifecycle = STARTING
        return StatusReport(slug=slug, lifecycle=lifecycle, probes=probes, meta=meta, enum_ok=False)

    containers = inspected.containers
    if not containers:
        if unresolved:
            return StatusReport(slug=slug, lifecycle=FAILED, probes=probes, meta=meta, enum_ok=True)
        lifecycle = STOPPED
        intent = str(journal.get("intent") or "")
        phase = str(journal.get("phase") or "")
        state = str(journal.get("state") or "")
        if intent in {"CREATING", "STARTING"} and not meta.get("creation_complete"):
            lifecycle = STARTING
        elif phase == "failed" or state == reg.OP_STATE_FAILED:
            lifecycle = FAILED
        return StatusReport(slug=slug, lifecycle=lifecycle, probes=probes, meta=meta, enum_ok=True)

    missing = [s for s in STANDARD_SERVICES if s not in containers]
    for svc, row in containers.items():
        probes.append(_container_probe(svc, row))
    for svc in missing:
        probes.append(ProbeResult(svc, UNHEALTHY, "missing"))

    ports = meta["ports"]
    gateway = int(ports["gateway"])
    base = f"http://127.0.0.1:{gateway}"
    env: dict[str, str] = {}
    env_path = deployment / ".env"
    if env_path.exists():
        env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))

    anon = env.get("ANON_KEY") or env.get("SUPABASE_PUBLISHABLE_KEY") or ""
    dash_user = env.get("DASHBOARD_USERNAME", "")
    dash_pass = env.get("DASHBOARD_PASSWORD", "")
    headers_api = {"apikey": anon, "Authorization": f"Bearer {anon}"} if anon else {}

    if not anon:
        probes.append(ProbeResult("rest", UNHEALTHY, "missing anon key"))
    else:
        rest = _http_probe(
            f"{base}/rest/v1/sbfleet_health_probe_missing",
            name="rest",
            headers=headers_api,
            expect_status={200, 404, 406},
        )
        probes.append(rest)

    probes.append(
        _http_probe(
            f"{base}/auth/v1/health",
            name="auth-http",
            headers={"apikey": anon} if anon else {},
            expect_status={200},
        )
    )

    probes.append(
        _http_probe(
            f"{base}/storage/v1/bucket",
            name="storage-http",
            headers=headers_api,
            expect_status={200},
        )
    )

    # Studio unauth: only explicit 401 (challenge) counts as auth-required healthy.
    unauth = _http_probe(
        f"{base}/project/default",
        name="studio-unauth-probe",
        expect_status={401},
        allow_redirects=False,
    )
    if unauth.status == HEALTHY and unauth.detail == "HTTP 401":
        probes.append(ProbeResult("studio-unauth", HEALTHY, "auth required"))
    elif (
        "URLError" in unauth.detail
        or "timeout" in unauth.detail.lower()
        or unauth.detail
        in {
            "TimeoutError",
            "URLError",
        }
    ):
        probes.append(ProbeResult("studio-unauth", UNHEALTHY, unauth.detail))
    elif unauth.detail == "HTTP 200":
        probes.append(ProbeResult("studio-unauth", UNHEALTHY, "unauthenticated access"))
    else:
        # Non-401 failure (timeout, connection error, 5xx, etc.) is not auth-required.
        probes.append(ProbeResult("studio-unauth", UNHEALTHY, unauth.detail))

    if dash_user and dash_pass:
        probes.append(
            _http_probe(
                f"{base}/project/default",
                name="studio",
                headers={"Authorization": _basic_auth_header(dash_user, dash_pass)},
                expect_status={200},
            )
        )
    else:
        probes.append(ProbeResult("studio", UNHEALTHY, "missing dashboard credentials"))

    # Meaningful SQL readiness — fail closed.
    probes.append(_sql_readiness(deployment, str(meta["compose_project"]), containers))

    # pg-meta via gateway: 200 OK, or 401/403 auth challenge means the route is live.
    probes.append(
        _http_probe(
            f"{base}/pg/",
            name="pg-meta",
            headers=headers_api,
            expect_status={200, 401, 403},
        )
    )

    if unresolved:
        # Runtime probes retained above as sub-observations; lifecycle is FAILED.
        return StatusReport(slug=slug, lifecycle=FAILED, probes=probes, meta=meta, enum_ok=True)

    statuses = [p.status for p in probes]
    if any(s == STARTING for s in statuses):
        lifecycle = STARTING
    elif any(s == UNHEALTHY for s in statuses) or missing:
        lifecycle = DEGRADED
    elif any(s == UNKNOWN for s in statuses):
        # Mandatory UNKNOWN cannot mean HEALTHY.
        lifecycle = UNKNOWN
    elif all(s == HEALTHY for s in statuses) and not missing:
        lifecycle = HEALTHY
    else:
        lifecycle = UNKNOWN

    return StatusReport(slug=slug, lifecycle=lifecycle, probes=probes, meta=meta, enum_ok=True)


def status_ok_flag(report: StatusReport) -> bool:
    """JSON ok means ready/HEALTHY only — never STARTING/STOPPED/FAILED/UNKNOWN."""
    return report.lifecycle == HEALTHY


def status_exit_code(report: StatusReport) -> int:
    """
    Central status exit map.

    Exit 0 for HEALTHY/STOPPED/STARTING means the status command successfully
    observed a valid known lifecycle state — not that the project is ready.
    READY is only lifecycle==HEALTHY (and JSON ok true).
    UNKNOWN/DEGRADED/UNHEALTHY → 7; FAILED → 1.
    """
    if report.lifecycle == HEALTHY:
        return 0
    if report.lifecycle == STOPPED:
        return 0
    if report.lifecycle == STARTING:
        return 0
    if report.lifecycle == FAILED:
        return 1
    if report.lifecycle in {DEGRADED, UNHEALTHY, UNKNOWN}:
        return 7
    return 1


def status_json(report: StatusReport, *, root: Path | None = None) -> dict[str, Any]:
    locations: dict[str, Any] = {}
    if root is not None:
        locations = _project_locations(root, report.slug, report.meta)
    journal = {}
    if root is not None:
        journal = reg.read_operation_journal(root, report.slug) or {}
    dash_user = None
    if root is not None:
        env_path = reg.project_dir(root, report.slug) / "deployment" / ".env"
        if env_path.is_file():
            try:
                env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
                dash_user = env.get("DASHBOARD_USERNAME")
            except Exception:  # noqa: BLE001
                dash_user = None
    data: dict[str, Any] = {
        "slug": report.slug,
        "lifecycle": report.lifecycle,
        "profile": report.meta.get("profile"),
        "public_url": report.meta.get("public_url"),
        "ports": report.meta.get("ports"),
        "enum_ok": report.enum_ok,
        "operation": {
            "intent": journal.get("intent"),
            "phase": journal.get("phase"),
        },
        "studio_auth": {
            "method": "basic",
            "username": dash_user,
            "password_in_env": True,
            "note": "Studio uses HTTP Basic Auth; password is in deployment/.env "
            "(use secrets --reveal --keys DASHBOARD_USERNAME,DASHBOARD_PASSWORD)",
        },
        "locations": locations,
        "probes": [{"name": p.name, "status": p.status, "detail": p.detail} for p in report.probes],
    }
    return {
        "format_version": 1,
        "ok": report.ok,
        "command": "status",
        "data": data,
        "warnings": [],
        "errors": [],
    }


_DISPLAY_STATUS = {
    HEALTHY: "healthy",
    UNHEALTHY: "unhealthy",
    STARTING: "waiting",
    UNKNOWN: "unknown",
    DEGRADED: "degraded",
    STOPPED: "stopped",
    FAILED: "failed",
}


def _display_status(status: str) -> str:
    return _DISPLAY_STATUS.get(status, status.lower())


def _probe_by_names(report: StatusReport, *names: str) -> ProbeResult | None:
    by_name = {p.name: p for p in report.probes}
    for name in names:
        if name in by_name:
            return by_name[name]
    return None


def format_status_human(report: StatusReport, *, root: Path | None = None) -> str:
    """Human-readable status with service breakdown, locations, and suggestions."""
    if report.lifecycle == STOPPED and not report.probes and report.enum_ok:
        lines = [
            report.slug,
            "",
            f"{'State':<12}{STOPPED}",
            f"{'Postgres':<12}stopped",
            f"{'Auth':<12}stopped",
            f"{'REST':<12}stopped",
            f"{'Gateway':<12}stopped",
            f"{'Studio':<12}unavailable",
        ]
    elif not report.enum_ok:
        lines = [
            report.slug,
            "",
            f"{'State':<12}{report.lifecycle}",
            f"{'Docker':<12}enumeration failed",
        ]
    else:
        db = _probe_by_names(report, "db")
        auth = _probe_by_names(report, "auth-http", "auth")
        rest = _probe_by_names(report, "rest")
        gw = _probe_by_names(report, "api-gw")
        studio = _probe_by_names(report, "studio")
        sql = _probe_by_names(report, "sql")

        def cell(probe: ProbeResult | None, *, missing: str = "unavailable") -> str:
            if probe is None:
                return missing
            return _display_status(probe.status)

        lines = [
            report.slug,
            "",
            f"{'State':<12}{report.lifecycle}",
            f"{'Postgres':<12}{cell(db, missing='unavailable')}",
            f"{'SQL':<12}{cell(sql)}",
            f"{'Auth':<12}{cell(auth)}",
            f"{'REST':<12}{cell(rest, missing='waiting')}",
            f"{'Gateway':<12}{cell(gw)}",
            f"{'Studio':<12}{cell(studio)}",
        ]

    if root is not None:
        loc = _project_locations(root, report.slug, report.meta)
        lines.extend(
            [
                "",
                "Locations",
                f"  project    {loc['project_root']}",
                f"  deployment {loc['deployment']}",
                f"  env        {loc['env_path']}",
                f"  metadata   {loc['metadata_path']}",
                f"  journal    {loc['journal_path']}",
                f"  backups    {loc['backup_dir']}",
                f"  nginx      {loc['nginx_path'] or '(absent)'}",
                f"  pin        {loc.get('upstream_ref')}",
                f"  verified   {loc.get('last_verified_upstream_ref') or '(none)'}",
                f"  backup     verification={loc.get('backup_verification')}",
            ]
        )
        if loc.get("local_studio_url"):
            lines.extend(["", "Studio", str(loc["local_studio_url"])])
            dash = None
            env_path = Path(str(loc["env_path"]))
            if env_path.is_file():
                try:
                    dash = up.parse_dotenv(env_path.read_text(encoding="utf-8")).get(
                        "DASHBOARD_USERNAME"
                    )
                except Exception:  # noqa: BLE001
                    dash = None
            lines.append("  Auth: HTTP Basic Auth (password in .env, not shown)")
            if dash:
                lines.append(f"  Username: {dash}")
            lines.append(f"  Env: {loc['env_path']}")
    else:
        ports = report.meta.get("ports") or {}
        gateway = ports.get("gateway")
        if gateway:
            lines.extend(["", "Studio", f"http://127.0.0.1:{gateway}/project/default"])
        elif report.meta.get("public_url"):
            lines.extend(
                ["", "Studio", f"{str(report.meta['public_url']).rstrip('/')}/project/default"]
            )

    if report.lifecycle in {DEGRADED, UNHEALTHY, FAILED, UNKNOWN}:
        failed = [
            p
            for p in report.probes
            if p.status in {UNHEALTHY, UNKNOWN}
            and p.name
            in {"auth", "auth-http", "db", "rest", "studio", "api-gw", "sql", "docker-compose"}
        ]
        lines.append("")
        lines.append("Suggested:")
        if failed:
            svc = failed[0].name
            if svc == "auth-http":
                svc = "auth"
            if svc not in {"docker-compose", "sql"}:
                lines.append(f"  /logs {svc}")
        else:
            lines.append("  /logs")
        lines.append("  /doctor")
        if report.lifecycle != STOPPED:
            lines.append("  /status")

    if report.lifecycle == STOPPED:
        lines.extend(["", "Suggested:", "  /start"])

    return "\n".join(lines)
