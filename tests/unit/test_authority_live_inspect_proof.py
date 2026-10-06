"""Complete fleet live-inspect proof (mounts/mode/networks/service label)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from tests.unit.test_compose_mutation_authority import _contract, _db_inspect, _Obs, _patch_invent

from sbfleet import authority as auth
from sbfleet import registry as reg


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _mutate_calls() -> list[list[str]]:
    return []


def _assert_refuses_zero_mutate(
    monkeypatch: pytest.MonkeyPatch,
    *,
    dep: Path,
    cp: str,
    fleet: str,
    proj: str,
    data: dict[str, Any] | None,
    match: str,
    empty_selector: bool = False,
) -> None:
    calls: list[list[str]] = []

    def tracking_run(argv, **kwargs):  # noqa: ANN001, ANN003
        calls.append(list(argv))
        return mock.MagicMock(ok=True, stdout="", stderr="", returncode=0)

    monkeypatch.setattr(auth, "run", tracking_run)

    if empty_selector:

        def ps(_f):
            return _Obs("PRESENT", {"ids": []})

        def inspect(args):
            target = args[-1]
            db_name = f"{cp}-db"
            if data is not None and (target == db_name or target == f"/{db_name}"):
                return _Obs("PRESENT", data)
            return _Obs("ABSENT")

        monkeypatch.setattr(auth, "_docker_ps_filter_ids", ps)
        monkeypatch.setattr(auth, "_docker_inspect_observation", inspect)
        monkeypatch.setattr(
            auth, "_docker_network_ls_ids", lambda *_a, **_k: _Obs("PRESENT", {"ids": []})
        )
        monkeypatch.setattr(
            auth, "_docker_volume_ls_names", lambda *_a, **_k: _Obs("PRESENT", {"names": []})
        )
    else:
        _patch_invent(monkeypatch, container_data=data)

    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match=match):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )
    mutate_verbs = {"stop", "start", "rm", "remove", "cp", "copy", "kill"}
    for argv in calls:
        joined = " ".join(argv)
        assert not any(v in argv for v in mutate_verbs), f"unexpected mutate dispatch: {joined}"


def test_extra_tmpfs_under_pgdata_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep)
    data["Mounts"].append(
        {
            "Type": "tmpfs",
            "Destination": "/var/lib/postgresql/data/base",
            "RW": True,
            "Mode": "rw",
        }
    )
    _assert_refuses_zero_mutate(
        monkeypatch,
        dep=dep,
        cp=cp,
        fleet=fleet,
        proj=proj,
        data=data,
        match="unapproved tmpfs",
    )


def test_missing_mount_mode_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep)
    for m in data["Mounts"]:
        m.pop("RW", None)
        m.pop("Mode", None)
        m.pop("ReadOnly", None)
    _assert_refuses_zero_mutate(
        monkeypatch,
        dep=dep,
        cp=cp,
        fleet=fleet,
        proj=proj,
        data=data,
        match="missing RW/Mode/ReadOnly",
    )


def test_contradictory_mount_mode_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep)
    data["Mounts"][0]["RW"] = True
    data["Mounts"][0]["Mode"] = "ro"
    data["Mounts"][0]["ReadOnly"] = True
    _assert_refuses_zero_mutate(
        monkeypatch,
        dep=dep,
        cp=cp,
        fleet=fleet,
        proj=proj,
        data=data,
        match="contradictory mount mode",
    )


def test_null_network_attachment_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(
        cp=cp,
        fleet=fleet,
        project=proj,
        deployment=dep,
        networks={f"{cp}_default": None},
    )
    _assert_refuses_zero_mutate(
        monkeypatch,
        dep=dep,
        cp=cp,
        fleet=fleet,
        proj=proj,
        data=data,
        match="null/malformed network attachment",
    )


def test_expected_name_missing_service_label_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep)
    del data["Config"]["Labels"]["com.docker.compose.service"]
    _assert_refuses_zero_mutate(
        monkeypatch,
        dep=dep,
        cp=cp,
        fleet=fleet,
        proj=proj,
        data=data,
        match="missing compose service",
        empty_selector=True,
    )


def test_positive_approved_profile_still_passes(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep)
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    inv = auth.invent_owned_resources(
        compose_project=cp,
        fleet_id=fleet,
        project_id=proj,
        deployment=dep,
        contract=contract,
    )
    assert len(inv.containers) == 1
    assert inv.containers[0].name.endswith("-db")


def test_integer_network_id_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep)
    data["NetworkSettings"]["Networks"][f"{cp}_default"] = {"NetworkID": 42}
    _assert_refuses_zero_mutate(
        monkeypatch,
        dep=dep,
        cp=cp,
        fleet=fleet,
        proj=proj,
        data=data,
        match="NetworkID must be string",
    )


def test_mode_null_with_rw_true_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep)
    data["Mounts"][0]["RW"] = True
    data["Mounts"][0]["Mode"] = None
    _assert_refuses_zero_mutate(
        monkeypatch,
        dep=dep,
        cp=cp,
        fleet=fleet,
        proj=proj,
        data=data,
        match="Mode is null",
    )


def test_malformed_network_id_types_refuse(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    for bad in (True, 3.14, [], {}, ""):
        data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep)
        data["NetworkSettings"]["Networks"][f"{cp}_default"] = {"NetworkID": bad}
        _assert_refuses_zero_mutate(
            monkeypatch,
            dep=dep,
            cp=cp,
            fleet=fleet,
            proj=proj,
            data=data,
            match="NetworkID|malformed|missing",
        )


def _seed_auth_project(home: Path, *, slug: str = "v4micro001") -> tuple[str, str, Path]:
    import uuid

    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    pdir = reg.project_dir(home, slug)
    pdir.mkdir(parents=True)
    cp = reg.compose_project_name(fid, pid)
    meta = {
        "format_version": 1,
        "slug": slug,
        "id": pid,
        "fleet_id": fid,
        "display_name": slug,
        "creation_complete": True,
        "compose_project": cp,
        "ports": {
            "gateway": 18000,
            "db_direct": 15432,
            "pooler_session": 15433,
            "pooler_transaction": 15434,
        },
        "upstream": {"ref": "v1.25.04", "sha": "a" * 40},
        "image_digests": {},
    }
    reg.atomic_write_json(pdir / "project.json", meta, mode=0o600)
    dep = pdir / "deployment"
    dep.mkdir(exist_ok=True)
    (dep / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (dep / "volumes/db/data").mkdir(parents=True)
    (dep / ".env").write_text(
        f"COMPOSE_PROJECT_NAME={cp}\nCOMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n",
        encoding="utf-8",
    )
    import os

    os.chmod(dep / ".env", 0o600)
    os.chmod(dep / "run.sh", 0o700)
    return fid, pid, dep


def test_authorize_mutation_integer_network_id_zero_mutate(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Production invent_live stop path: NetworkID 42 refuses before yield; zero mutate."""
    slug = "v4micro001"
    fid, pid, dep = _seed_auth_project(home, slug=slug)
    cp = reg.compose_project_name(fid, pid)
    data = _db_inspect(cp=cp, fleet=fid, project=pid, deployment=dep)
    data["NetworkSettings"]["Networks"][f"{cp}_default"] = {"NetworkID": 42}
    contract = _contract(cp=cp, fleet=fid, project=pid, deployment=dep)
    calls: list[list[str]] = []

    def tracking_run(argv, **kwargs):  # noqa: ANN001, ANN003
        calls.append(list(argv))
        return mock.MagicMock(ok=True, stdout="", stderr="", returncode=0)

    monkeypatch.setattr(auth, "run", tracking_run)
    _patch_invent(monkeypatch, container_data=data)
    monkeypatch.setattr(auth, "build_project_contract", lambda *a, **k: contract)
    monkeypatch.setattr(auth, "_validate_effective_compose", lambda *a, **k: None)
    monkeypatch.setattr(auth, "_verify_env_selectors", lambda *a, **k: None)
    yielded = False
    with pytest.raises(auth.AuthorityError, match="NetworkID must be string|live Docker"):
        with auth.authorize_mutation(
            home,
            slug,
            intent="stop",
            invent_live=True,
            validate_compose=False,
            skip_pin_vendor_check=True,
            ignore_unresolved_journal=True,
        ):
            yielded = True
    assert yielded is False
    mutate_verbs = {"stop", "start", "rm", "remove", "cp", "copy", "kill"}
    for argv in calls:
        assert not any(v in argv for v in mutate_verbs), argv


def test_authorize_mutation_mode_null_zero_mutate(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    slug = "v4micro001b"
    fid, pid, dep = _seed_auth_project(home, slug=slug)
    cp = reg.compose_project_name(fid, pid)
    data = _db_inspect(cp=cp, fleet=fid, project=pid, deployment=dep)
    data["Mounts"][0]["Mode"] = None
    contract = _contract(cp=cp, fleet=fid, project=pid, deployment=dep)
    calls: list[list[str]] = []

    def tracking_run(argv, **kwargs):  # noqa: ANN001, ANN003
        calls.append(list(argv))
        return mock.MagicMock(ok=True, stdout="", stderr="", returncode=0)

    monkeypatch.setattr(auth, "run", tracking_run)
    _patch_invent(monkeypatch, container_data=data)
    monkeypatch.setattr(auth, "build_project_contract", lambda *a, **k: contract)
    monkeypatch.setattr(auth, "_validate_effective_compose", lambda *a, **k: None)
    monkeypatch.setattr(auth, "_verify_env_selectors", lambda *a, **k: None)
    yielded = False
    with pytest.raises(auth.AuthorityError, match="Mode is null|live Docker"):
        with auth.authorize_mutation(
            home,
            slug,
            intent="stop",
            invent_live=True,
            validate_compose=False,
            skip_pin_vendor_check=True,
            ignore_unresolved_journal=True,
        ):
            yielded = True
    assert yielded is False
    mutate_verbs = {"stop", "start", "rm", "remove", "cp", "copy", "kill"}
    for argv in calls:
        assert not any(v in argv for v in mutate_verbs), argv
