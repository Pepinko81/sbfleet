"""Observer contract: shared model, failures, redaction, and no write dispatch."""

import asyncio
import json
import uuid
from datetime import datetime, timezone

import pytest
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from sbfleet import fleet, health
from sbfleet import registry as reg
from sbfleet.cli import main
from sbfleet.dashboard import make_application, render
from sbfleet.mcp_server import create_server

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
SECRET = "super-secret-never-observe-456789"


@pytest.fixture
def managed(tmp_path, monkeypatch):
    root = reg.ensure_root(tmp_path / "fleet")
    fid = reg.fleet_id(root)
    for index, slug in enumerate(("healthy", "stopped", "failed", "unknown", "starting")):
        pid = str(uuid.uuid4())
        reg.write_project(
            root,
            {
                "slug": slug,
                "format_version": 1,
                "display_name": f"Project {SECRET}",
                "id": pid,
                "fleet_id": fid,
                "compose_project": reg.compose_project_name(fid, pid),
                "ports": dict(
                    zip(fleet.PORTS, range(20000 + index * 4, 20004 + index * 4), strict=True)
                ),
                "upstream": {"ref": "self-hosted/v1.2.3", "sha": "a" * 40},
                "public_url": f"https://user:{SECRET}@example.com/?key={SECRET}",
                "password": SECRET,
                "image_digests": {SECRET: SECRET},
            },
        )
        deployment = reg.project_dir(root, slug) / "deployment"
        deployment.mkdir()
        (deployment / ".env").write_text(f"POSTGRES_PASSWORD={SECRET}\n")
        (deployment / ".env").chmod(0o600)

    def status(root, slug, *, read_only=False):
        assert read_only
        return health.StatusReport(
            slug,
            slug.upper(),
            probes=[health.ProbeResult("db", "HEALTHY", SECRET)],
            enum_ok=slug != "unknown",
            meta=reg.read_project(root, slug),
        )

    monkeypatch.setattr(health, "collect_status", status)
    return root


def test_snapshot_contract(managed):
    snapshot = fleet.collect_snapshot(managed, now=NOW)
    data = json.loads(fleet.snapshot_json(snapshot))
    assert data["schema_version"] == "sbfleet.fleet.v1"
    assert [p["slug"] for p in data["projects"]] == sorted(
        ["healthy", "stopped", "failed", "unknown", "starting"]
    )
    assert data["totals"] == {
        "projects": 5,
        "healthy": 1,
        "stopped": 1,
        "failed": 1,
        "unknown": 1,
        "other": 1,
        "recovery_verified_backups": 0,
        "needing_attention": 5,
    }
    serialized = fleet.snapshot_json(snapshot)
    assert SECRET not in serialized
    assert "public_url" not in serialized
    assert "password" not in serialized
    assert serialized == fleet.snapshot_json(fleet.collect_snapshot(managed, now=NOW))
    assert not snapshot.observation_complete
    assert all(p.update_available is None for p in snapshot.projects)
    assert not any(managed.rglob(".run-home"))


def test_unknown_does_not_initialize(tmp_path, capsys):
    root = tmp_path / "absent"
    assert main(["--home", str(root), "status", "--all", "--json"]) == 7
    data = json.loads(capsys.readouterr().out)
    assert data["errors"] == ["registry_observation_failed"]
    assert not root.exists()


def test_registry_failure_and_corrupt_project(managed, monkeypatch):
    (managed / "projects" / "broken").mkdir()
    snapshot = fleet.collect_snapshot(managed)
    broken = next(p for p in snapshot.projects if p.slug == "broken")
    assert broken.state == "UNKNOWN"
    assert broken.errors == ["project_observation_failed"]
    monkeypatch.setattr(reg, "list_projects", lambda _: (_ for _ in ()).throw(OSError(SECRET)))
    assert SECRET not in fleet.snapshot_json(fleet.collect_snapshot(managed))


def test_backup_authority_and_age(managed, monkeypatch):
    meta = reg.read_project(managed, "healthy")
    meta["last_backup_id"] = "backup-1"
    reg.write_project(managed, meta)
    monkeypatch.setattr(
        fleet,
        "require_recovery_backup",
        lambda *_: {
            "verified_at": "2026-01-01T00:00:00Z",
            "identity": SECRET,
        },
    )
    item = next(p for p in fleet.collect_snapshot(managed, now=NOW).projects if p.slug == "healthy")
    assert item.backup.status == "RECOVERY_VERIFIED"
    assert item.backup.age_seconds == 86400
    monkeypatch.setattr(
        fleet, "require_recovery_backup", lambda *_: (_ for _ in ()).throw(RuntimeError(SECRET))
    )
    item = next(p for p in fleet.collect_snapshot(managed, now=NOW).projects if p.slug == "healthy")
    assert item.backup.status == "UNKNOWN"
    assert SECRET not in item.model_dump_json()


def test_symlink_and_untrusted_backup_identifiers(managed, monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("must not read untrusted receipt path")

    monkeypatch.setattr(fleet, "require_recovery_backup", forbidden)
    meta = reg.read_project(managed, "healthy")
    meta["last_backup_id"] = "../../secret"
    assert fleet._backup(managed, meta, NOW).status == "UNKNOWN"
    meta["last_backup_id"] = "ok"
    (managed / "backups" / meta["id"]).symlink_to(tmp_path)
    assert fleet._backup(managed, meta, NOW).status == "UNKNOWN"


def test_grammar_and_json(managed, capsys):
    assert main(["--home", str(managed), "status", "--all", "--json"]) == 7
    assert json.loads(capsys.readouterr().out)["schema_version"] == "sbfleet.fleet.v1"
    assert main(["status"]) == 2
    assert main(["status", "healthy", "--all"]) == 2


def test_dashboard_start_navigation_refresh_quit(managed):
    async def exercise():
        with create_pipe_input() as pipe:
            app = make_application(managed, input=pipe, output=DummyOutput())
            task = asyncio.create_task(app.run_async())
            await asyncio.sleep(0.15)
            pipe.send_text("\x1b[Br")
            await asyncio.sleep(0.15)
            pipe.send_text("q")
            await asyncio.wait_for(task, 3)

    asyncio.run(exercise())
    text = render(fleet.collect_snapshot(managed))
    assert "READ-ONLY" in text and "Selected:" in text
    assert SECRET not in text
    with pytest.raises(ValueError):
        make_application(managed, refresh=1)


def test_every_mcp_tool_schema_and_secrets(managed):
    async def exercise():
        server = create_server(managed)
        tools = await server.list_tools()
        names = {t.name for t in tools}
        assert names == {
            "fleet_summary",
            "list_projects",
            "project_status",
            "project_connection_info",
            "backup_status",
            "doctor_summary",
            "schema_diff",
            "migration_plan",
        }
        for tool in tools:
            assert tool.annotations.readOnlyHint
            assert not tool.annotations.destructiveHint
            assert tool.outputSchema
            arguments = {"slug": "healthy"} if "slug" in tool.inputSchema["properties"] else {}
            if tool.name in {"schema_diff", "migration_plan"}:
                arguments = {"source": "healthy", "target": "healthy"}
            result = await server.call_tool(tool.name, arguments)
            assert SECRET not in str(result)
        result = await server.call_tool("project_status", {"slug": "../../secrets"})
        assert "UNKNOWN" in str(result)  # another project has an observation error
        with pytest.raises(Exception, match="Unknown tool"):
            await server.call_tool("remove", {"slug": "healthy"})

    asyncio.run(exercise())


def test_observers_never_dispatch_mutations(managed, monkeypatch):
    from sbfleet import projects

    def forbidden(*args, **kwargs):
        pytest.fail("observer attempted mutation")

    for name in ("ensure_root", "atomic_write_json", "project_lock", "registry_lock"):
        monkeypatch.setattr(reg, name, forbidden)
    for name in dir(projects):
        if name.startswith(("create_project", "start_project", "stop_project", "restart_project")):
            monkeypatch.setattr(projects, name, forbidden)
    assert render(fleet.collect_snapshot(managed))
    assert main(["--home", str(managed), "dashboard", "--once"]) == 0
    asyncio.run(create_server(managed).call_tool("fleet_summary", {}))


def test_observer_container_inspection_does_not_mkdir(tmp_path, monkeypatch):
    from sbfleet.process import ProcessResult

    monkeypatch.setattr(health, "run", lambda *a, **k: ProcessResult([], 0, "[]", ""))
    health.inspect_containers_result(tmp_path, "test", read_only=True)
    assert not (tmp_path / ".run-home").exists()


def test_missing_projects_directory_is_unknown(tmp_path):
    root = reg.ensure_root(tmp_path / "fleet")
    (root / "projects").rmdir()
    snapshot = fleet.collect_snapshot(root)
    assert not snapshot.observation_complete
    assert snapshot.errors == ["registry_observation_failed"]
    assert not (root / "projects").exists()


def test_unresolved_operation_and_status_exception(managed, monkeypatch):
    reg.write_operation_journal(
        managed,
        "healthy",
        {
            "format_version": 1,
            "intent": "UPDATING",
            "state": "in_progress",
            "phase": "promote",
            "operation_id": SECRET,
        },
    )
    snapshot = fleet.collect_snapshot(managed)
    item = next(p for p in snapshot.projects if p.slug == "healthy")
    assert item.operation_unresolved is True
    assert "operation" in item.attention
    assert SECRET not in fleet.snapshot_json(snapshot)

    def broken(*a, **k):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(health, "collect_status", broken)
    snapshot = fleet.collect_snapshot(managed)
    assert all(p.state == "UNKNOWN" for p in snapshot.projects)
    assert not snapshot.observation_complete
    assert SECRET not in fleet.snapshot_json(snapshot)


def test_unreadable_redaction_source_fails_closed(managed):
    env = managed / "projects" / "healthy" / "deployment" / ".env"
    env.unlink()
    env.mkdir()
    snapshot = fleet.collect_snapshot(managed)
    item = next(p for p in snapshot.projects if p.slug == "healthy")
    assert item.state == "UNKNOWN"
    assert SECRET not in fleet.snapshot_json(snapshot)


def test_metadata_changed_during_status_is_unknown(managed, monkeypatch):
    monkeypatch.setattr(
        health,
        "collect_status",
        lambda *a, **k: health.StatusReport("healthy", "HEALTHY", meta={"id": "changed"}),
    )
    snapshot = fleet.collect_snapshot(managed)
    assert not snapshot.observation_complete
    assert all(p.state == "UNKNOWN" for p in snapshot.projects)


def test_boolean_port_is_unknown_not_an_integer_endpoint(managed):
    meta = reg.read_project(managed, "healthy")
    meta["ports"]["gateway"] = True
    reg.write_project(managed, meta)
    item = next(p for p in fleet.collect_snapshot(managed).projects if p.slug == "healthy")
    assert item.state == "UNKNOWN"
    assert item.ports == {}
    assert item.endpoints == {}


def test_service_summary_separates_containers_from_endpoint_health(managed, monkeypatch):
    def status(root, slug, *, read_only=False):
        assert read_only
        return health.StatusReport(
            slug,
            "DEGRADED",
            probes=[health.ProbeResult(name, "HEALTHY") for name in fleet.STANDARD_SERVICES]
            + [health.ProbeResult("rest", "UNHEALTHY"), health.ProbeResult("studio", "UNHEALTHY")],
            meta=reg.read_project(root, slug),
        )

    monkeypatch.setattr(health, "collect_status", status)
    item = fleet.collect_snapshot(managed).projects[0]
    assert len(item.services) == len(fleet.STANDARD_SERVICES)
    assert all(service.state == "HEALTHY" for service in item.services)
    assert item.runtime_state == "RUNNING"
    assert item.health_state == "DEGRADED"
    assert any(check.state == "UNHEALTHY" for check in item.checks)


def test_probe_enumeration_order_does_not_change_json(managed, monkeypatch):
    reverse = False

    def status(root, slug, *, read_only=False):
        probes = [health.ProbeResult(name, "HEALTHY") for name in fleet.STANDARD_SERVICES]
        if reverse:
            probes.reverse()
        return health.StatusReport(
            slug, "HEALTHY", probes=probes, meta=reg.read_project(root, slug)
        )

    monkeypatch.setattr(health, "collect_status", status)
    first = fleet.snapshot_json(fleet.collect_snapshot(managed, now=NOW))
    reverse = True
    assert fleet.snapshot_json(fleet.collect_snapshot(managed, now=NOW)) == first
