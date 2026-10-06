"""Disposable Docker proof: configure Studio names require stop/start to apply."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet import configure as cfg
from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.health import HEALTHY, collect_status
from sbfleet.process import run
from sbfleet.projects import create_project, start_project, stop_project
from sbfleet.projects_remove import remove_project

pytestmark = pytest.mark.docker


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    r = run(
        ["docker", "info"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=30.0,
        check=False,
    )
    return r.ok


def _cleanup_remove(root: Path, slug: str) -> None:
    op = reg.project_dir(root, slug) / "operation.json"
    if op.exists() or op.is_symlink():
        op.unlink()
    remove_project(root, slug, yes=True, no_backup=True)


@pytest.fixture()
def disposable_home(tmp_path: Path):
    if not _docker_ok():
        pytest.skip("docker unavailable")
    run_id = uuid.uuid4().hex[:12]
    root = reg.ensure_root(tmp_path / f"sbfleet-test-{run_id}")
    fleet = reg.fleet_id(root)
    yield {"root": root, "run_id": run_id, "fleet_id": fleet}
    import fixture_cleanup

    fixture_cleanup.cleanup_labeled_fleet_resources(fleet_id=fleet)


def _studio_env(deployment: Path, compose_project: str) -> dict[str, str]:
    inspected = run(
        ["docker", "compose", "ps", "--format", "json"],
        cwd=deployment,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(deployment / ".run-home"),
            "COMPOSE_PROJECT_NAME": compose_project,
            "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
            "COMPOSE_PATH_SEPARATOR": ":",
        },
        timeout=60.0,
        check=False,
    )
    assert inspected.ok, inspected.stderr
    text = (inspected.stdout or "").strip()
    rows: list = []
    try:
        data = json.loads(text)
        rows = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in text.splitlines():
            if line.strip():
                rows.append(json.loads(line))
    cid = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        svc = row.get("Service") or ""
        if svc == "studio" or str(row.get("Name", "")).endswith("-studio"):
            cid = row.get("ID") or row.get("Container") or row.get("Name")
            break
    assert cid, "studio container missing"
    insp = run(
        ["docker", "inspect", "--format", "{{json .Config.Env}}", str(cid)],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=30.0,
        check=False,
    )
    assert insp.ok, insp.stderr
    items = json.loads((insp.stdout or "").strip())
    raw: dict[str, str] = {}
    for item in items:
        if isinstance(item, str) and "=" in item:
            k, v = item.split("=", 1)
            if k in {
                "DEFAULT_ORGANIZATION_NAME",
                "DEFAULT_PROJECT_NAME",
                "STUDIO_DEFAULT_ORGANIZATION",
                "STUDIO_DEFAULT_PROJECT",
            }:
                raw[k] = v
    # Normalize to STUDIO_DEFAULT_* keys for assertions.
    out: dict[str, str] = {}
    if "DEFAULT_ORGANIZATION_NAME" in raw:
        out["STUDIO_DEFAULT_ORGANIZATION"] = raw["DEFAULT_ORGANIZATION_NAME"]
    elif "STUDIO_DEFAULT_ORGANIZATION" in raw:
        out["STUDIO_DEFAULT_ORGANIZATION"] = raw["STUDIO_DEFAULT_ORGANIZATION"]
    if "DEFAULT_PROJECT_NAME" in raw:
        out["STUDIO_DEFAULT_PROJECT"] = raw["DEFAULT_PROJECT_NAME"]
    elif "STUDIO_DEFAULT_PROJECT" in raw:
        out["STUDIO_DEFAULT_PROJECT"] = raw["STUDIO_DEFAULT_PROJECT"]
    return out


def test_configure_running_requires_stop_start(disposable_home: dict) -> None:
    root: Path = disposable_home["root"]
    slug = f"cfg{uuid.uuid4().hex[:8]}"
    try:
        meta = create_project(
            root,
            slug,
            display_name="Cfg",
            organization_name="OldOrg",
            studio_project_name="OldProj",
            start=True,
        )
        report = collect_status(root, slug)
        assert report.lifecycle == HEALTHY

        live_before = _studio_env(
            reg.project_dir(root, slug) / "deployment", str(meta["compose_project"])
        )
        assert live_before.get("STUDIO_DEFAULT_ORGANIZATION") == "OldOrg"

        result = cfg.configure_project(
            root,
            slug,
            organization_name_value="NewOrg",
            studio_project_value="NewProj",
            display_name="Configured App",
        )
        assert result.mutated
        assert result.applied.status in {"no", "unknown"}
        text = cfg.format_configure_human(result)
        assert "restart does not refresh" in text.lower()
        assert "stop" in text and "start" in text

        # Files configured; running Env still old until recreate.
        env = up.parse_dotenv(
            (reg.project_dir(root, slug) / "deployment" / ".env").read_text(encoding="utf-8")
        )
        assert env["STUDIO_DEFAULT_ORGANIZATION"] == "NewOrg"
        assert env["STUDIO_DEFAULT_PROJECT"] == "NewProj"
        live_mid = _studio_env(
            reg.project_dir(root, slug) / "deployment", str(meta["compose_project"])
        )
        assert live_mid.get("STUDIO_DEFAULT_ORGANIZATION") == "OldOrg"

        meta2 = reg.read_project(root, slug)
        assert meta2["display_name"] == "Configured App"
        assert meta2["slug"] == slug
        assert meta2["id"] == meta["id"]
        assert meta2["compose_project"] == meta["compose_project"]
        assert meta2["ports"] == meta["ports"]

        stop_project(root, slug)
        start_project(root, slug, timeout=600)
        assert collect_status(root, slug).lifecycle == HEALTHY

        # Survive stop/start on disk + applied in container.
        env2 = up.parse_dotenv(
            (reg.project_dir(root, slug) / "deployment" / ".env").read_text(encoding="utf-8")
        )
        assert env2["STUDIO_DEFAULT_ORGANIZATION"] == "NewOrg"
        live_after = _studio_env(
            reg.project_dir(root, slug) / "deployment", str(meta["compose_project"])
        )
        assert live_after.get("STUDIO_DEFAULT_ORGANIZATION") == "NewOrg"
        assert live_after.get("STUDIO_DEFAULT_PROJECT") == "NewProj"

        readback = cfg.configure_project(root, slug)
        assert readback.applied.status == "yes"
    finally:
        try:
            _cleanup_remove(root, slug)
        except Exception:
            pass
