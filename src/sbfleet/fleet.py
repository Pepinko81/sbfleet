"""Versioned, allowlisted fleet observations shared by CLI, dashboard and MCP.

No registry initialization, locks, lifecycle dispatch or remote update queries.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sbfleet import health
from sbfleet import registry as reg
from sbfleet.backup import require_recovery_backup
from sbfleet.compose import STANDARD_SERVICES
from sbfleet.process import project_diagnostic_redactor, sanitize_configured_diagnostic

State = Literal["HEALTHY", "STOPPED", "FAILED", "UNKNOWN", "STARTING", "DEGRADED", "UNHEALTHY"]
STATES = {"HEALTHY", "STOPPED", "FAILED", "UNKNOWN", "STARTING", "DEGRADED", "UNHEALTHY"}
PORTS = ("gateway", "db_direct", "pooler_session", "pooler_transaction")


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BackupObservation(Model):
    status: Literal["RECOVERY_VERIFIED", "NONE", "UNKNOWN"] = "UNKNOWN"
    verified_at: str | None = None
    age_seconds: int | None = None


class Check(Model):
    name: str
    state: State = "UNKNOWN"


class ProjectObservation(Model):
    slug: str
    display_name: str | None = None
    project_id: str | None = None
    fleet_id: str | None = None
    state: State = "UNKNOWN"
    runtime_state: Literal["RUNNING", "STOPPED", "UNKNOWN"] = "UNKNOWN"
    health_state: State = "UNKNOWN"
    upstream_ref: str | None = None
    upstream_sha: str | None = None
    studio_url: str | None = None
    endpoints: dict[str, str] = Field(default_factory=dict)
    ports: dict[str, int] = Field(default_factory=dict)
    services: list[Check] = Field(default_factory=list)
    resource_usage: Literal["UNKNOWN"] = "UNKNOWN"
    backup: BackupObservation = Field(default_factory=BackupObservation)
    operation_unresolved: bool | None = None
    update_available: bool | None = None
    sandbox: Literal["NOT_APPLICABLE"] = "NOT_APPLICABLE"
    checks: list[Check] = Field(default_factory=list)
    attention: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class Totals(Model):
    projects: int = 0
    healthy: int = 0
    stopped: int = 0
    failed: int = 0
    unknown: int = 0
    other: int = 0
    recovery_verified_backups: int = 0
    needing_attention: int = 0


class FleetSnapshot(Model):
    schema_version: Literal["sbfleet.fleet.v1"] = "sbfleet.fleet.v1"
    observed_at: str
    observation_complete: bool = True
    totals: Totals = Field(default_factory=Totals)
    projects: list[ProjectObservation] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def _backup(root: Path, meta: dict, now: datetime) -> BackupObservation:
    backup_id = meta.get("last_backup_id")
    if not backup_id:
        return BackupObservation(status="NONE")
    # Existing backup authority expects trusted identifiers; validate before joining paths.
    if not isinstance(backup_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", backup_id):
        return BackupObservation()
    directory = root / "backups" / meta["id"]
    for path in (root / "backups", directory, directory / f"{backup_id}.json"):
        if path.is_symlink():
            return BackupObservation()
    try:
        receipt = require_recovery_backup(root, meta)
        verified = datetime.fromisoformat(
            str(receipt.get("verified_at", "")).replace("Z", "+00:00")
        )
        if verified.tzinfo is None or verified > now:
            return BackupObservation()
        return BackupObservation(
            status="RECOVERY_VERIFIED",
            verified_at=verified.astimezone(timezone.utc).isoformat(),
            age_seconds=int((now - verified).total_seconds()),
        )
    except Exception:
        # Never forward exception strings, archive paths, identities or receipt contents.
        return BackupObservation()


def _project(root: Path, record: reg.ProjectRecord, now: datetime) -> ProjectObservation:
    slug = record.path.name
    item = ProjectObservation(slug="unknown")
    try:
        reg.validate_slug(slug)
        item.slug = slug
        if not record.ok:
            raise ValueError("invalid registry row")
        meta = reg.validate_project_identity(root, reg.read_project(root, slug))
        deployment = record.path / "deployment"
        reg.assert_managed_entry(record.path, under=root / "projects", expect_dir=True)
        reg.assert_managed_entry(deployment, under=record.path, expect_dir=True)
        reg.assert_secret_file(deployment / ".env")
        redactor = project_diagnostic_redactor(deployment)
        item.slug = sanitize_configured_diagnostic(slug, redactor=redactor)
        item.display_name = sanitize_configured_diagnostic(
            str(meta.get("display_name") or slug), redactor=redactor, max_len=120
        )
        item.display_name = "".join(c for c in item.display_name if c.isprintable())
        item.project_id = meta["id"]
        item.fleet_id = meta["fleet_id"]
        upstream = meta["upstream"]
        # Only reviewed-looking refs and hexadecimal commits; never arbitrary URL credentials.
        ref = upstream.get("ref", "")
        if re.fullmatch(r"self-hosted/v[0-9]+\.[0-9]+\.[0-9]+", ref):
            item.upstream_ref = ref
        sha = upstream.get("sha", "")
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            item.upstream_sha = sha
        if any(type(meta["ports"][key]) is not int for key in PORTS):
            raise ValueError("non-integer allocated port")
        item.ports = {k: meta["ports"][k] for k in PORTS}
        item.endpoints = {k: f"127.0.0.1:{v}" for k, v in item.ports.items()}
        item.studio_url = f"http://127.0.0.1:{item.ports['gateway']}/project/default"
        journal = reg.read_operation_journal(root, slug)
        item.operation_unresolved = reg.journal_is_unresolved(journal)
        item.backup = _backup(root, meta, now)
        report = health.collect_status(root, slug, read_only=True)
        if report.meta != meta:
            raise ValueError("project changed during observation")
        item.state = report.lifecycle if report.lifecycle in STATES else "UNKNOWN"
        item.health_state = item.state
        allowed_checks = set(STANDARD_SERVICES) | {
            "sql",
            "rest",
            "auth-http",
            "storage-http",
            "studio",
            "studio-unauth",
            "pg-meta",
            "operation",
            "docker-compose",
        }
        item.checks = [
            Check(name=p.name, state=p.status if p.status in STATES else "UNKNOWN")
            for p in report.probes
            if p.name in allowed_checks
        ]
        # Status emits container probes before endpoint probes that share names
        # (notably rest and studio). Keep the first probe for each service.
        services: dict[str, Check] = {}
        for check in item.checks:
            if check.name in STANDARD_SERVICES:
                services.setdefault(check.name, check)
        item.services = sorted(services.values(), key=lambda check: check.name)
        item.checks.sort(key=lambda check: (check.name, check.state))
        if report.enum_ok:
            if item.state == "STOPPED":
                item.runtime_state = "STOPPED"
            elif item.services and all(p.state == "HEALTHY" for p in item.services):
                item.runtime_state = "RUNNING"
        else:
            item.errors.append("runtime_observation_failed")
    except Exception:
        item.errors.append("project_observation_failed")
    if item.state not in {"HEALTHY", "STOPPED"}:
        item.attention.append("runtime")
    if item.operation_unresolved is not False:
        item.attention.append("operation")
    if item.backup.status != "RECOVERY_VERIFIED":
        item.attention.append("backup")
    return item


def collect_snapshot(root: Path, *, now: datetime | None = None) -> FleetSnapshot:
    """Observe existing fleet only. Stable ordering; times use one UTC observation clock."""
    now = now or datetime.now(timezone.utc)
    snapshot = FleetSnapshot(observed_at=now.isoformat())
    try:
        reg.assert_managed_entry(root, under=root, expect_dir=True)
        reg.assert_managed_entry(root / "projects", under=root, expect_dir=True)
        reg.fleet_id(root)
        records = reg.list_projects(root)
        snapshot.projects = [_project(root, record, now) for record in records]
    except Exception:
        snapshot.observation_complete = False
        snapshot.errors = ["registry_observation_failed"]
    for item in snapshot.projects:
        totals = snapshot.totals
        totals.projects += 1
        field = (
            item.state.lower()
            if item.state in {"HEALTHY", "STOPPED", "FAILED", "UNKNOWN"}
            else "other"
        )
        setattr(totals, field, getattr(totals, field) + 1)
        totals.recovery_verified_backups += item.backup.status == "RECOVERY_VERIFIED"
        totals.needing_attention += bool(item.attention)
        if item.errors:
            snapshot.observation_complete = False
    return snapshot


def snapshot_json(snapshot: FleetSnapshot) -> str:
    import json

    return json.dumps(snapshot.model_dump(), sort_keys=True, ensure_ascii=True)
