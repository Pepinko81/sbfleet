"""Doctor validator matrix."""

from __future__ import annotations

import io
import json
import os
import uuid
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet.cli import EXIT_OK, EXIT_PREREQUISITE, EXIT_SAFETY, EXIT_UNHEALTHY
from sbfleet.doctor import (
    CLASS_HEALTH,
    CLASS_INFORMATIONAL,
    CLASS_PREREQUISITE,
    CLASS_SAFETY,
    _exit_for_checks,
    run_doctor,
)


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def test_exit_priority_safety_beats_prerequisite_and_health():
    checks = [
        {"id": "node", "status": "fail", "class": CLASS_PREREQUISITE},
        {"id": "health", "status": "fail", "class": CLASS_HEALTH},
        {"id": "secret-file", "status": "fail", "class": CLASS_SAFETY},
    ]
    assert _exit_for_checks(checks) == EXIT_SAFETY


def test_exit_priority_prerequisite_beats_health():
    checks = [
        {"id": "docker", "status": "fail", "class": CLASS_PREREQUISITE},
        {"id": "health", "status": "fail", "class": CLASS_HEALTH},
    ]
    assert _exit_for_checks(checks) == EXIT_PREREQUISITE


def test_informational_unknown_exits_ok():
    checks = [
        {
            "id": "runtime-images-recorded",
            "status": "unknown",
            "class": CLASS_INFORMATIONAL,
        },
        {"id": "age", "status": "warn", "class": CLASS_INFORMATIONAL},
    ]
    assert _exit_for_checks(checks) == EXIT_OK


def test_authority_unknown_is_nonzero():
    assert (
        _exit_for_checks([{"id": "compose-contract", "status": "unknown", "class": CLASS_SAFETY}])
        == EXIT_SAFETY
    )
    assert (
        _exit_for_checks(
            [{"id": "docker-daemon", "status": "unknown", "class": CLASS_PREREQUISITE}]
        )
        == EXIT_PREREQUISITE
    )
    assert (
        _exit_for_checks([{"id": "health", "status": "unknown", "class": CLASS_HEALTH}])
        == EXIT_UNHEALTHY
    )


def _stub_host_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sbfleet.doctor.shutil.which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr("sbfleet.doctor.require_local_node", lambda: None)

    class FakeUsage:
        free = 50 * 1024**3

    monkeypatch.setattr("sbfleet.doctor.shutil.disk_usage", lambda p: FakeUsage())

    def fake_run(argv, **kwargs):
        from sbfleet.process import ProcessResult

        return ProcessResult(list(argv), 0, "ok\n", "")

    monkeypatch.setattr("sbfleet.doctor.run", fake_run)


def _seed_project(home: Path, *, slug: str, **extra) -> dict:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    pdir = reg.project_dir(home, slug)
    pdir.mkdir(parents=True)
    meta = {
        "format_version": 1,
        "slug": slug,
        "id": pid,
        "fleet_id": fid,
        "display_name": slug,
        "creation_complete": True,
        "ports": {
            "gateway": 18000,
            "db_direct": 15432,
            "pooler_session": 15433,
            "pooler_transaction": 15434,
        },
        "upstream": {"ref": "v1.25.04", "sha": "deadbeef"},
        "image_digests": {},
    }
    meta.update(extra)
    reg.atomic_write_json(pdir / "project.json", meta, mode=0o600)
    (pdir / "deployment").mkdir(exist_ok=True)
    env_path = pdir / "deployment" / ".env"
    env_path.write_text("POSTGRES_PASSWORD=synthetic-password-xx\n", encoding="utf-8")
    os.chmod(env_path, 0o600)
    return meta


def _patch_project_deps(monkeypatch: pytest.MonkeyPatch, *, lifecycle: str = "STOPPED") -> None:
    monkeypatch.setattr("sbfleet.doctor.PINNED_REF", "v1.25.04")
    monkeypatch.setattr("sbfleet.upstream.verify_deployment_vendor", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.upstream.verify_stamp_matches_meta", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.branding.doctor_auth_checks", lambda *a, **k: [])
    monkeypatch.setattr("sbfleet.compose.compose_config_json", lambda *a, **k: {"services": {}})
    monkeypatch.setattr("sbfleet.compose.vendor_expected_images", lambda *a, **k: {})
    monkeypatch.setattr("sbfleet.compose.validate_resolved_config", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.forced_compose_env", lambda *a, **k: {})

    class FakeContract:
        pass

    monkeypatch.setattr("sbfleet.authority.build_project_contract", lambda *a, **k: FakeContract())
    monkeypatch.setattr("sbfleet.authority._validate_effective_compose", lambda *a, **k: None)

    class Inv:
        residuals: list = []
        containers: list = []

    monkeypatch.setattr("sbfleet.authority.invent_owned_resources", lambda **k: Inv())

    class Report:
        def __init__(self) -> None:
            self.lifecycle = lifecycle
            self.probes = []

    monkeypatch.setattr("sbfleet.health.collect_status", lambda *a, **k: Report())


def test_doctor_missing_backup_archive_is_safety(home: Path, monkeypatch: pytest.MonkeyPatch):
    _stub_host_ok(monkeypatch)
    bid = str(uuid.uuid4())
    meta = _seed_project(
        home,
        slug="docproj",
        last_backup_id=bid,
        last_backup_verification="recovery",
    )
    _patch_project_deps(monkeypatch)
    bdir = home / "backups" / meta["id"]
    bdir.mkdir(parents=True)
    reg.atomic_write_json(
        bdir / f"{bid}.json",
        {
            "format_version": 1,
            "backup_id": bid,
            "project_id": meta["id"],
            "verification": "recovery",
            "ciphertext_bytes": 100,
            "ciphertext_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
        },
        mode=0o600,
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(home, project="docproj", sandbox=None, as_json=True)
    payload = json.loads(buf.getvalue())
    by_id = {c["id"]: c for c in payload["data"]["checks"]}
    assert by_id["backup"]["status"] == "fail"
    assert by_id["backup"]["class"] == CLASS_SAFETY
    assert code == EXIT_SAFETY
    assert payload["ok"] is False


def test_doctor_unsafe_secret_file(home: Path, monkeypatch: pytest.MonkeyPatch):
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="secproj")
    env_path = reg.project_dir(home, "secproj") / "deployment" / ".env"
    os.chmod(env_path, 0o644)
    _patch_project_deps(monkeypatch)
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(home, project="secproj", sandbox=None, as_json=True)
    payload = json.loads(buf.getvalue())
    by_id = {c["id"]: c for c in payload["data"]["checks"]}
    assert by_id["secret-file"]["status"] == "fail"
    assert by_id["secret-file"]["class"] == CLASS_SAFETY
    assert code == EXIT_SAFETY


def test_doctor_unresolved_journal(home: Path, monkeypatch: pytest.MonkeyPatch):
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="jrnl")
    _patch_project_deps(monkeypatch)
    reg.atomic_write_json(
        reg.project_dir(home, "jrnl") / "operation.json",
        {
            "format_version": 1,
            "intent": "REMOVING",
            "phase": "deleting",
            "state": "IN_PROGRESS",
        },
        mode=0o600,
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(home, project="jrnl", sandbox=None, as_json=True)
    payload = json.loads(buf.getvalue())
    by_id = {c["id"]: c for c in payload["data"]["checks"]}
    assert by_id["journal"]["status"] == "fail"
    assert "REMOVING" in by_id["journal"]["reason"]
    assert code == EXIT_SAFETY


def test_doctor_docker_missing_is_prerequisite(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(
        "sbfleet.doctor.shutil.which", lambda n: None if n == "docker" else f"/bin/{n}"
    )
    monkeypatch.setattr("sbfleet.doctor.require_local_node", lambda: None)

    class FakeUsage:
        free = 50 * 1024**3

    monkeypatch.setattr("sbfleet.doctor.shutil.disk_usage", lambda p: FakeUsage())
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(tmp_path, project=None, sandbox=None, as_json=True)
    payload = json.loads(buf.getvalue())
    by_id = {c["id"]: c for c in payload["data"]["checks"]}
    assert by_id["docker"]["status"] == "fail"
    assert by_id["docker-daemon"]["status"] == "unknown"
    assert code == EXIT_PREREQUISITE
    assert payload["ok"] is False


def test_doctor_unhealthy_lifecycle(home: Path, monkeypatch: pytest.MonkeyPatch):
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="unhl")
    _patch_project_deps(monkeypatch, lifecycle="UNHEALTHY")
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(home, project="unhl", sandbox=None, as_json=True)
    payload = json.loads(buf.getvalue())
    by_id = {c["id"]: c for c in payload["data"]["checks"]}
    assert by_id["health"]["status"] == "fail"
    assert code == EXIT_UNHEALTHY


def test_doctor_foreign_ownership_residuals(home: Path, monkeypatch: pytest.MonkeyPatch):
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="own")
    _patch_project_deps(monkeypatch)

    class Inv:
        residuals = ["foreign-or-mislabeled-container:evil"]
        containers: list = []

    monkeypatch.setattr("sbfleet.authority.invent_owned_resources", lambda **k: Inv())
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(home, project="own", sandbox=None, as_json=True)
    payload = json.loads(buf.getvalue())
    by_id = {c["id"]: c for c in payload["data"]["checks"]}
    assert by_id["live-ownership"]["status"] == "fail"
    assert code == EXIT_SAFETY


def test_doctor_corrupt_vendor(home: Path, monkeypatch: pytest.MonkeyPatch):
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="vend")
    _patch_project_deps(monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("vendor digest mismatch")

    monkeypatch.setattr("sbfleet.upstream.verify_deployment_vendor", boom)
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(home, project="vend", sandbox=None, as_json=True)
    payload = json.loads(buf.getvalue())
    by_id = {c["id"]: c for c in payload["data"]["checks"]}
    assert by_id["vendor-integrity"]["status"] == "fail"
    assert code == EXIT_SAFETY
