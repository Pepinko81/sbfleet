"""Local stdio MCP adapter. The only capability is fleet observation."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from sbfleet.fleet import (
    BackupObservation,
    Check,
    FleetSnapshot,
    Model,
    ProjectObservation,
    collect_snapshot,
)
from sbfleet.schema import MigrationPlan, SchemaDiff
from sbfleet.schema import migration_plan as collect_plan
from sbfleet.schema import schema_diff as collect_diff


class ProjectResult(Model):
    schema_version: str = "sbfleet.fleet.v1"
    project: ProjectObservation | None = None
    error: str | None = None


class ConnectionResult(Model):
    schema_version: str = "sbfleet.fleet.v1"
    endpoints: dict[str, str] = Field(default_factory=dict)
    studio_url: str | None = None
    error: str | None = None


class BackupResult(Model):
    schema_version: str = "sbfleet.fleet.v1"
    backup: BackupObservation | None = None
    error: str | None = None


class DoctorResult(Model):
    schema_version: str = "sbfleet.fleet.v1"
    scope: str = "snapshot runtime checks; not full host/sandbox doctor"
    checks: list[Check] = Field(default_factory=list)
    attention: list[str] = Field(default_factory=list)
    error: str | None = None


def create_server(root: Path) -> FastMCP:
    server = FastMCP("sbfleet", instructions="Local-only read-only fleet observations. No secrets.")
    annotations = ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    )

    def lookup(slug: str) -> ProjectResult:
        snapshot = collect_snapshot(root)
        for project in snapshot.projects:
            if project.slug == slug:
                return ProjectResult(project=project)
        return ProjectResult(error="NOT_FOUND" if snapshot.observation_complete else "UNKNOWN")

    @server.tool(annotations=annotations)
    def fleet_summary() -> FleetSnapshot:
        """Complete canonical fleet snapshot with totals and observation errors."""
        return collect_snapshot(root)

    @server.tool(annotations=annotations)
    def list_projects() -> FleetSnapshot:
        """List managed projects with canonical status and completeness information."""
        return collect_snapshot(root)

    @server.tool(annotations=annotations)
    def project_status(slug: str) -> ProjectResult:
        """Observe a managed project by exact slug; UNKNOWN if observation fails."""
        return lookup(slug)

    @server.tool(annotations=annotations)
    def project_connection_info(slug: str) -> ConnectionResult:
        """Loopback endpoints only. Never credentials, connection passwords or keys."""
        result = lookup(slug)
        if result.project is None:
            return ConnectionResult(error=result.error)
        return ConnectionResult(
            endpoints=result.project.endpoints,
            studio_url=result.project.studio_url,
            error="UNKNOWN" if result.project.errors else None,
        )

    @server.tool(annotations=annotations)
    def backup_status(slug: str) -> BackupResult:
        """Recovery-verified backup availability and age; no archive or identity paths."""
        result = lookup(slug)
        return BackupResult(
            backup=result.project.backup if result.project else None, error=result.error
        )

    @server.tool(annotations=annotations)
    def doctor_summary(slug: str) -> DoctorResult:
        """Summarize snapshot runtime checks; does not run full host/sandbox doctor."""
        result = lookup(slug)
        if result.project is None:
            return DoctorResult(error=result.error)
        return DoctorResult(
            checks=result.project.checks,
            attention=result.project.attention,
            error="UNKNOWN" if result.project.errors else None,
        )

    @server.tool(annotations=annotations)
    def schema_diff(source: str, target: str) -> SchemaDiff:
        """Read-only catalog diff: SOURCE desired, TARGET current. No arbitrary SQL."""
        return collect_diff(root, source, target)

    @server.tool(annotations=annotations)
    def migration_plan(source: str, target: str) -> MigrationPlan:
        """Preview classifications only. Never executes DDL or applies migrations."""
        return collect_plan(root, source, target)

    return server


def run_mcp(root: Path) -> int:
    create_server(root).run(transport="stdio")
    return 0
