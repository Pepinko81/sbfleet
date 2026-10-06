"""Cleanup capacity fail closed."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from sbfleet import backup as bak
from sbfleet.backup_recovery import cleanup_verifier_resources


def test_cleanup_order_containers_before_volumes() -> None:
    """Attached volumes must not be deleted while the container still exists."""
    resources = {
        "volumes": [{"id": "vol-a", "name": "vol-a"}],
        "containers": [{"id": "ctr-a"}],
        "networks": [{"id": "net-a"}],
    }
    calls: list[list[str]] = []

    def fake_docker(argv: list[str], **kwargs):  # noqa: ANN003
        calls.append(list(argv))

        class R:
            ok = True
            stdout = "fleet|ver|op"
            stderr = ""

        # After rm, subsequent inspect for residual check returns not ok.
        if (
            argv[:3] == ["docker", "rm", "-f"]
            or argv[:3]
            == [
                "docker",
                "volume",
                "rm",
            ]
            or argv[:3] == ["docker", "network", "rm"]
        ):
            return R()
        if "inspect" in argv:
            # Ownership inspect succeeds; residual existence inspect after delete fails.
            if any(x in argv for x in ("ctr-a", "vol-a", "net-a")) and "--format" not in argv:
                # Simplified: after a matching rm appears, existence fails.
                for c in calls:
                    if c[:3] == ["docker", "rm", "-f"] and argv[-1] == "ctr-a":
                        rr = R()
                        rr.ok = False
                        return rr
                    if c[:3] == ["docker", "volume", "rm"] and argv[-1] == "vol-a":
                        rr = R()
                        rr.ok = False
                        return rr
                    if c[:3] == ["docker", "network", "rm"] and argv[-1] == "net-a":
                        rr = R()
                        rr.ok = False
                        return rr
            return R()
        return R()

    with mock.patch("sbfleet.backup_recovery._docker", side_effect=fake_docker):
        errs = cleanup_verifier_resources(
            resources, fleet_id="fleet", verifier_id="ver", operation_id="op"
        )
    assert not any(e.startswith("residual ") for e in errs)
    # First destructive op must be container rm, then volume, then network.
    destructive = [
        c
        for c in calls
        if c[:3] == ["docker", "rm", "-f"]
        or c[:3] == ["docker", "volume", "rm"]
        or c[:3] == ["docker", "network", "rm"]
    ]
    assert destructive[0][:3] == ["docker", "rm", "-f"]
    assert destructive[1][:3] == ["docker", "volume", "rm"]
    assert destructive[2][:3] == ["docker", "network", "rm"]


def test_cleanup_deletion_failure_journals_residual() -> None:
    resources = {
        "containers": [{"id": "ctr-stuck"}],
        "volumes": [],
        "networks": [],
    }

    def fake_docker(argv: list[str], **kwargs):  # noqa: ANN003
        class R:
            ok = True
            stdout = "fleet|ver|op"
            stderr = "busy"

        if argv[:3] == ["docker", "rm", "-f"]:
            r = R()
            r.ok = False
            return r
        if argv[:2] == ["docker", "inspect"] and "--format" not in argv:
            # Still exists
            return R()
        return R()

    with mock.patch("sbfleet.backup_recovery._docker", side_effect=fake_docker):
        errs = cleanup_verifier_resources(
            resources, fleet_id="fleet", verifier_id="ver", operation_id="op"
        )
    assert any("residual container id=ctr-stuck" in e for e in errs)
    assert resources.get("cleanup_residuals")


def test_disk_preflight_unknown_size_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    dep = root / "proj" / "deployment"
    (dep / "volumes" / "db" / "data").mkdir(parents=True)
    (dep / "volumes" / "storage").mkdir(parents=True)
    monkeypatch.setattr(bak, "_disk_free_bytes", lambda p: 10 * 1024**3)
    monkeypatch.setattr(bak, "_measure_tree_bytes", lambda p: None)
    monkeypatch.setattr(bak, "_docker_root_dir", lambda: root)
    with pytest.raises(bak.BackupError, match="unable to establish source data size"):
        bak.disk_preflight(root, dep)


def test_disk_preflight_unknown_free_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    dep = root / "proj" / "deployment"
    (dep / "volumes" / "db" / "data").mkdir(parents=True)
    (dep / "volumes" / "storage").mkdir(parents=True)
    monkeypatch.setattr(bak, "_measure_tree_bytes", lambda p: 100)
    monkeypatch.setattr(bak, "_docker_root_dir", lambda: root)
    monkeypatch.setattr(bak, "_disk_free_bytes", lambda p: None)
    with pytest.raises(bak.BackupError, match="unable to establish free disk"):
        bak.disk_preflight(root, dep)


def test_disk_preflight_low_capacity_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    dep = root / "proj" / "deployment"
    data = dep / "volumes" / "db" / "data"
    storage = dep / "volumes" / "storage"
    data.mkdir(parents=True)
    storage.mkdir(parents=True)
    (data / "x").write_bytes(b"x" * 100)
    (storage / "y").write_bytes(b"y" * 100)
    monkeypatch.setattr(bak, "_docker_root_dir", lambda: root)
    monkeypatch.setattr(bak, "_disk_free_bytes", lambda p: 100)
    with pytest.raises(bak.BackupError, match="insufficient disk"):
        bak.disk_preflight(root, dep, reserve_bytes=1)
