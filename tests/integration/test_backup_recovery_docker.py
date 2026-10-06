"""Integration: recovery helpers + sentinel survival (regression suite)."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet.archive_safe import ArchiveSafetyError, build_tar_from_tree, safe_extract
from sbfleet.backup_recovery import cleanup_verifier_resources, parse_pg_controldata
from sbfleet.process import run

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


def _run(argv: list[str], **kwargs):
    return run(
        argv,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=60.0,
        check=False,
        **kwargs,
    )


@pytest.fixture()
def docker_ready():
    if not _docker_ok():
        pytest.skip("docker unavailable")


def test_sentinel_survives_verifier_cleanup(docker_ready, tmp_path: Path):
    run_id = uuid.uuid4().hex[:12]
    fleet = f"fleet-{run_id}"
    verifier = f"rv-{run_id}"
    op = f"op-{run_id}"
    sentinel_name = f"sbfleet-sentinel-{run_id}"
    s = _run(
        [
            "docker",
            "volume",
            "create",
            "--label",
            "io.sbfleet.role=sentinel",
            sentinel_name,
        ]
    )
    assert s.ok
    insp = _run(["docker", "volume", "inspect", "--format", "{{.Name}}", sentinel_name])
    before = (insp.stdout or "").strip()
    assert before == sentinel_name

    owned = f"sbfleet-rv-{run_id}-pgdata"
    c = _run(
        [
            "docker",
            "volume",
            "create",
            "--label",
            f"io.sbfleet.fleet={fleet}",
            "--label",
            f"io.sbfleet.project={verifier}",
            "--label",
            f"io.sbfleet.operation={op}",
            "--label",
            "io.sbfleet.role=recovery-verifier",
            owned,
        ]
    )
    assert c.ok
    resources = {"volumes": [{"name": owned, "id": owned}], "containers": [], "networks": []}
    errs = cleanup_verifier_resources(
        resources, fleet_id=fleet, verifier_id=verifier, operation_id=op
    )
    assert not any("refuse" in e for e in errs)
    after = _run(["docker", "volume", "inspect", "--format", "{{.Name}}", sentinel_name])
    assert after.ok
    assert (after.stdout or "").strip() == before
    _run(["docker", "volume", "rm", sentinel_name])


def test_sentinel_survives_attached_verifier_volume_cleanup(docker_ready, tmp_path: Path):
    """Containers deleted before volumes so attached owned volumes are removable."""
    run_id = uuid.uuid4().hex[:12]
    fleet = f"fleet-{run_id}"
    verifier = f"rv-{run_id}"
    op = f"op-{run_id}"
    sentinel_name = f"sbfleet-sentinel-att-{run_id}"
    s = _run(
        [
            "docker",
            "volume",
            "create",
            "--label",
            "io.sbfleet.role=sentinel",
            sentinel_name,
        ]
    )
    assert s.ok
    before = _run(["docker", "volume", "inspect", "--format", "{{.Name}}", sentinel_name])
    assert before.ok

    owned_vol = f"sbfleet-rv-{run_id}-pgdata"
    c = _run(
        [
            "docker",
            "volume",
            "create",
            "--label",
            f"io.sbfleet.fleet={fleet}",
            "--label",
            f"io.sbfleet.project={verifier}",
            "--label",
            f"io.sbfleet.operation={op}",
            "--label",
            "io.sbfleet.role=recovery-verifier",
            owned_vol,
        ]
    )
    assert c.ok
    cname = f"sbfleet-rv-{run_id}-db"
    start = _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            cname,
            "--network",
            "none",
            "--label",
            f"io.sbfleet.fleet={fleet}",
            "--label",
            f"io.sbfleet.project={verifier}",
            "--label",
            f"io.sbfleet.operation={op}",
            "--label",
            "io.sbfleet.role=recovery-verifier",
            "-v",
            f"{owned_vol}:/data",
            "alpine:3.20",
            "sleep",
            "60",
        ]
    )
    assert start.ok, (start.stderr or start.stdout or "")[:300]
    cid = (start.stdout or "").strip()
    resources = {
        "volumes": [{"name": owned_vol, "id": owned_vol}],
        "containers": [{"name": cname, "id": cid or cname}],
        "networks": [],
    }
    errs = cleanup_verifier_resources(
        resources, fleet_id=fleet, verifier_id=verifier, operation_id=op
    )
    assert not any(e.startswith("residual ") for e in errs), errs
    gone = _run(["docker", "volume", "inspect", owned_vol])
    assert not gone.ok
    after = _run(["docker", "volume", "inspect", "--format", "{{.Name}}", sentinel_name])
    assert after.ok
    assert (after.stdout or "").strip() == (before.stdout or "").strip()
    _run(["docker", "volume", "rm", sentinel_name])


def test_safe_extract_roundtrip_docker_host(tmp_path: Path, docker_ready):
    src = tmp_path / "src"
    src.mkdir()
    (src / "postgres").mkdir()
    (src / "postgres" / "PG_VERSION").write_text("15\n", encoding="utf-8")
    tar_path = tmp_path / "t.tar"
    build_tar_from_tree(src, tar_path)
    out = tmp_path / "out"
    safe_extract(tar_path, out)
    assert (out / "postgres" / "PG_VERSION").read_text(encoding="utf-8") == "15\n"


def test_parse_controldata_helper_unit():
    facts = parse_pg_controldata("Database cluster state: shut down\n")
    assert "shut down" in facts["Database cluster state"]


def test_malicious_tar_refused(tmp_path: Path):
    import io
    import tarfile

    tar_path = tmp_path / "evil.tar"
    with tarfile.open(tar_path, "w:") as tf:
        info = tarfile.TarInfo(name="../escape")
        data = b"x"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(ArchiveSafetyError):
        safe_extract(tar_path, tmp_path / "out")
