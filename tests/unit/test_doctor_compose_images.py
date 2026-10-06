"""Doctor compose images."""

from __future__ import annotations

import io
import json
import os
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sbfleet import registry as reg
from sbfleet.cli import EXIT_OK, EXIT_SAFETY, EXIT_UNHEALTHY
from sbfleet.doctor import (
    CLASS_INFORMATIONAL,
    CLASS_SAFETY,
    _current_image_facts,
    _exit_for_checks,
    run_doctor,
)


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _stub_host_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sbfleet.doctor.shutil.which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr("sbfleet.doctor.require_local_node", lambda: None)

    class FakeUsage:
        free = 50 * 1024**3

    monkeypatch.setattr("sbfleet.doctor.shutil.disk_usage", lambda p: FakeUsage())
    monkeypatch.setattr(
        "sbfleet.doctor.run",
        lambda argv, **kwargs: MagicMock(ok=True, stdout="ok\n", stderr="", returncode=0),
    )


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


def _patch_baseline(monkeypatch: pytest.MonkeyPatch, *, lifecycle: str = "STOPPED") -> None:
    monkeypatch.setattr("sbfleet.doctor.PINNED_REF", "v1.25.04")
    monkeypatch.setattr("sbfleet.upstream.verify_deployment_vendor", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.upstream.verify_stamp_matches_meta", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.branding.doctor_auth_checks", lambda *a, **k: [])
    monkeypatch.setattr("sbfleet.registry.assert_secret_file", lambda *a, **k: None)

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
            self.probes: list = []

    monkeypatch.setattr("sbfleet.health.collect_status", lambda *a, **k: Report())


def _run_json(home: Path, slug: str) -> tuple[int, dict]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(home, project=slug, sandbox=None, as_json=True)
    return code, json.loads(buf.getvalue())


def _check(payload: dict, cid: str) -> dict:
    for c in payload["data"]["checks"]:
        if c["id"] == cid:
            return c
    raise AssertionError(f"missing check {cid}")


def test_vendor_image_map_unavailable_fails_compose(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="img1")
    _patch_baseline(monkeypatch)

    def boom(*_a, **_k):  # noqa: ANN002, ANN003
        raise RuntimeError("vendor image map unavailable")

    monkeypatch.setattr("sbfleet.authority.build_project_contract", boom)
    code, payload = _run_json(home, "img1")
    c = _check(payload, "compose-contract")
    assert c["status"] == "fail"
    assert c["class"] == CLASS_SAFETY
    assert "vendor image map" in c["reason"] or "unavailable" in c["reason"]
    assert code == EXIT_SAFETY
    assert payload["ok"] is False


def test_malformed_docker_inspect_current_unknown(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="img2")
    _patch_baseline(monkeypatch)

    class FakeInspect:
        ok = True
        containers = {"db": {"Image": "x", "ID": ""}}  # missing id
        error = None

    monkeypatch.setattr("sbfleet.health.inspect_containers_result", lambda *a, **k: FakeInspect())
    code, payload = _run_json(home, "img2")
    c = _check(payload, "runtime-images-current")
    assert c["status"] == "unknown"
    assert c["class"] == CLASS_INFORMATIONAL
    assert "inspected=" not in c["reason"]
    assert "malformed" in c["reason"] or "missing" in c["reason"]
    assert code == EXIT_OK  # informational unknown


def test_runtime_image_mismatch_vs_recorded(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_host_ok(monkeypatch)
    _seed_project(
        home,
        slug="img3",
        image_digests={
            "db": {
                "status": "RECORDED",
                "image_id": "sha256:oldid",
                "image_ref": "old:ref",
                "digest": "d1",
                "platform": "linux/amd64",
            }
        },
    )
    _patch_baseline(monkeypatch)

    class FakeInspect:
        ok = True
        containers = {"db": {"Image": "new:ref", "ID": "ctr1"}}
        error = None

    monkeypatch.setattr("sbfleet.health.inspect_containers_result", lambda *a, **k: FakeInspect())

    def fake_run(argv, **kwargs):  # noqa: ANN003
        if argv and argv[0] == "docker" and "inspect" in argv:
            return MagicMock(ok=True, stdout="sha256:newid|new:ref\n", stderr="", returncode=0)
        return MagicMock(ok=True, stdout="ok\n", stderr="", returncode=0)

    monkeypatch.setattr("sbfleet.doctor.run", fake_run)
    code, payload = _run_json(home, "img3")
    c = _check(payload, "runtime-images-current")
    assert c["status"] == "fail"
    assert "CURRENT" in c["reason"] and "RECORDED" in c["reason"]
    # informational FAIL → treated as unhealthy
    assert code == EXIT_UNHEALTHY


def test_stopped_no_runtime_image(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="img4")
    _patch_baseline(monkeypatch, lifecycle="STOPPED")

    class FakeInspect:
        ok = True
        containers: dict = {}
        error = None

    monkeypatch.setattr("sbfleet.health.inspect_containers_result", lambda *a, **k: FakeInspect())
    code, payload = _run_json(home, "img4")
    c = _check(payload, "runtime-images-current")
    assert c["status"] == "unknown"
    assert "CURRENT" in c["reason"]
    assert "inspected=" not in c["reason"]
    assert code == EXIT_OK


def test_current_inspect_failure(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="img5")
    _patch_baseline(monkeypatch)

    class FakeInspect:
        ok = False
        containers: dict = {}
        error = "compose ps failed"

    monkeypatch.setattr("sbfleet.health.inspect_containers_result", lambda *a, **k: FakeInspect())
    code, payload = _run_json(home, "img5")
    c = _check(payload, "runtime-images-current")
    assert c["status"] == "unknown"
    assert code == EXIT_OK


def test_stale_recorded_metadata(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_host_ok(monkeypatch)
    _seed_project(
        home,
        slug="img6",
        image_digests={"db": {"status": "UNKNOWN", "reason": "stale"}},
    )
    _patch_baseline(monkeypatch)

    class FakeInspect:
        ok = True
        containers: dict = {}
        error = None

    monkeypatch.setattr("sbfleet.health.inspect_containers_result", lambda *a, **k: FakeInspect())
    code, payload = _run_json(home, "img6")
    rec = _check(payload, "runtime-images-recorded")
    assert rec["status"] == "unknown"
    assert "RECORDED" in rec["reason"]
    assert code == EXIT_OK


def test_recovery_receipt_failure(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_host_ok(monkeypatch)
    bid = str(uuid.uuid4())
    meta = _seed_project(
        home,
        slug="img7",
        last_backup_id=bid,
        last_backup_verification="recovery",
    )
    _patch_baseline(monkeypatch)
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
    # No archive file → require_recovery_backup fails
    code, payload = _run_json(home, "img7")
    c = _check(payload, "backup")
    assert c["status"] == "fail"
    assert c["class"] == CLASS_SAFETY
    assert code == EXIT_SAFETY


def test_mixed_doctor_failures_exit_safety(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_host_ok(monkeypatch)
    _seed_project(home, slug="img8")
    _patch_baseline(monkeypatch, lifecycle="UNHEALTHY")
    monkeypatch.setattr(
        "sbfleet.authority.build_project_contract",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("contract unavailable")),
    )
    code, payload = _run_json(home, "img8")
    assert _check(payload, "compose-contract")["status"] == "fail"
    assert _check(payload, "health")["status"] == "fail"
    assert code == EXIT_SAFETY  # safety beats unhealthy


def test_current_image_facts_helper_no_ps_count_lie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    dep = tmp_path / "deployment"
    dep.mkdir()

    class FakeInspect:
        ok = True
        containers = {"db": {"Image": "img:1", "ID": "abc"}}
        error = None

    monkeypatch.setattr("sbfleet.health.inspect_containers_result", lambda *a, **k: FakeInspect())
    monkeypatch.setattr(
        "sbfleet.doctor.run",
        lambda argv, **kwargs: MagicMock(
            ok=True, stdout="sha256:abc|img:1\n", stderr="", returncode=0
        ),
    )
    out = _current_image_facts(dep, "proj", recorded={})
    assert out["status"] == "ok"
    assert out["inspected_services"] == 1
    assert "count" not in out or out.get("inspected_services") == 1


def test_exit_matrix_informational_unknown_ok():
    assert (
        _exit_for_checks(
            [
                {
                    "id": "runtime-images-current",
                    "status": "unknown",
                    "class": CLASS_INFORMATIONAL,
                }
            ]
        )
        == EXIT_OK
    )
