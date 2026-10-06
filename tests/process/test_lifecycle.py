"""Module tests."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from sbfleet import projects as proj
from sbfleet import registry as reg
from sbfleet.process import ProcessResult


@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    from sbfleet import upstream as up

    home = reg.ensure_root(tmp_path / "home")
    fid = reg.fleet_id(home)
    import uuid

    pid = str(uuid.uuid4())
    slug = "life"
    ports = {
        "gateway": 32001,
        "db_direct": 32002,
        "pooler_session": 32003,
        "pooler_transaction": 32004,
    }
    # Seed upstream cache so authorize pin/vendor check is fail-closed but passable.
    cache = home / "cache" / "upstream" / up.PINNED_SHA
    docker = cache / "docker"
    docker.mkdir(parents=True)
    for rel in up.CRITICAL_VENDOR_FILES:
        path = docker / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith(".sh"):
            path.write_text("#!/bin/sh\n", encoding="utf-8")
        else:
            path.write_text("services: {}\n" + ("x" * 120), encoding="utf-8")
    digests = up.critical_vendor_digests(docker)
    import json

    (cache / ".sbfleet-cache.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "ref": up.PINNED_REF,
                "sha": up.PINNED_SHA,
                "repo": up.OFFICIAL_REPO,
                "critical_digests": digests,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": "Life",
        "created_at": "2026-09-26T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": ports,
        "domain": None,
        "public_url": "http://127.0.0.1:32001",
        "upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA},
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": True,
    }
    reg.write_project(home, meta)
    dep = reg.project_dir(home, slug) / "deployment"
    dep.mkdir(parents=True)
    # Vendor files match cache digests for authorize verify_deployment_vendor.
    for rel in up.CRITICAL_VENDOR_FILES:
        src = docker / rel
        dest = dep / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
    up.write_version_stamp(dep, ref=up.PINNED_REF, sha=up.PINNED_SHA)
    run_sh = dep / "run.sh"
    # Preserve digest-matching run.sh content but make it executable and log calls.
    # Override with instrumented script AFTER stamp/vendor verify would fail — instead
    # monkeypatch vendor verify in tests that mutate run.sh, OR keep instrumented copy
    # and also update cache digests after rewrite.
    run_sh.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$1\" >> ./calls.log\nexit 0\n",
        encoding="utf-8",
    )
    os.chmod(run_sh, run_sh.stat().st_mode | stat.S_IXUSR)
    # Re-anchor cache digests to instrumented run.sh so authorize passes.
    digests = up.critical_vendor_digests(dep)
    # Map dep-relative critical paths: digests keys are relative to docker/
    (cache / ".sbfleet-cache.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "ref": up.PINNED_REF,
                "sha": up.PINNED_SHA,
                "repo": up.OFFICIAL_REPO,
                "critical_digests": digests,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    # Sync cache docker files to match digests recorded from deployment.
    for rel in up.CRITICAL_VENDOR_FILES:
        (docker / rel).write_bytes((dep / rel).read_bytes())
    cp = str(meta["compose_project"])
    from sbfleet import compose as c

    c.write_override(
        dep,
        c.render_override(
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            gateway_port=ports["gateway"],
            db_direct_port=ports["db_direct"],
            pooler_session_port=ports["pooler_session"],
            pooler_transaction_port=ports["pooler_transaction"],
        ),
    )
    (dep / ".env").write_text(
        f"COMPOSE_PROJECT_NAME={cp}\n"
        "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n"
        "COMPOSE_PATH_SEPARATOR=:\n"
        "JWT_SECRET=secret-token-value-xyz\n",
        encoding="utf-8",
    )
    os.chmod(dep / ".env", 0o600)
    (dep / "volumes").mkdir()
    return home, slug


def _stub_contract(home: Path, slug: str):
    from sbfleet import compose as c

    meta = reg.read_project(home, slug)
    cp = str(meta["compose_project"])
    fleet = str(meta["fleet_id"])
    project = str(meta["id"])
    services = {
        name: c.ServiceContract(
            service=name,
            container_name=f"{cp}-{name}",
            image_ref=f"example/{name}:1",
            mounts=(),
            networks=frozenset({f"{cp}_default"}),
            required_labels=frozenset(
                {
                    ("io.sbfleet.fleet", fleet),
                    ("io.sbfleet.project", project),
                    ("com.docker.compose.project", cp),
                    ("com.docker.compose.service", name),
                }
            ),
        )
        for name in c.STANDARD_SERVICES
    }
    return c.ApprovedProfileContract(
        compose_project=cp,
        fleet_id=fleet,
        project_id=project,
        services=services,
        expected_network=f"{cp}_default",
        expected_volumes=frozenset({f"{cp}_db-config", f"{cp}_deno-cache"}),
    )


def test_start_stop_invoke_run_sh(
    project: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, slug = project
    from sbfleet.health import HEALTHY, ContainerInspectResult, StatusReport

    monkeypatch.setattr(
        "sbfleet.authority.build_project_contract",
        lambda *a, **k: _stub_contract(home, slug),
    )
    monkeypatch.setattr(
        "sbfleet.authority._validate_effective_compose",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        "sbfleet.authority.invent_owned_resources",
        lambda **k: __import__("sbfleet.authority", fromlist=["OwnedInventory"]).OwnedInventory(),
    )
    monkeypatch.setattr(
        "sbfleet.health.collect_status",
        lambda *a, **k: StatusReport(slug, HEALTHY, enum_ok=True),
    )
    monkeypatch.setattr(
        "sbfleet.health.inspect_containers_result",
        lambda *a, **k: ContainerInspectResult(ok=True, containers={}),
    )
    monkeypatch.setattr(
        "sbfleet.projects._record_runtime_images",
        lambda *a, **k: None,
    )
    proj.start_project(home, slug, timeout=5)
    proj.stop_project(home, slug)
    log = (reg.project_dir(home, slug) / "deployment" / "calls.log").read_text(encoding="utf-8")
    assert "start" in log
    assert "stop" in log


def test_restart_refused_when_not_running(
    project: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, slug = project

    monkeypatch.setattr(
        "sbfleet.authority.build_project_contract",
        lambda *a, **k: _stub_contract(home, slug),
    )
    monkeypatch.setattr(
        "sbfleet.authority._validate_effective_compose",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        "sbfleet.authority.invent_owned_resources",
        lambda **k: __import__("sbfleet.authority", fromlist=["OwnedInventory"]).OwnedInventory(),
    )

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        if argv[:3] == ["docker", "compose", "ps"]:
            return ProcessResult(argv=list(argv), returncode=0, stdout="", stderr="")
        return ProcessResult(argv=list(argv), returncode=0, stdout="", stderr="")

    monkeypatch.setattr("sbfleet.projects.run", fake_run)
    with pytest.raises(proj.ProjectError, match="not running"):
        proj.restart_project(home, slug)


def test_logs_redacts_secret(
    project: tuple[Path, str], monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    home, slug = project

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        return ProcessResult(
            argv=list(argv),
            returncode=0,
            stdout="token=secret-token-value-xyz leaked\n",
            stderr="",
        )

    monkeypatch.setattr("sbfleet.projects.run", fake_run)
    proj.project_logs(home, slug, tail=10)
    out = capsys.readouterr().out
    assert "secret-token-value-xyz" not in out
    assert "[REDACTED]" in out
