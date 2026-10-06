"""Compose mutation authority."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from sbfleet import authority as auth
from sbfleet import compose as c
from sbfleet import registry as reg


def _contract(
    *,
    cp: str = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb",
    fleet: str = "a" * 32,
    project: str = "b" * 32,
    deployment: Path,
    db_bind_src: Path | None = None,
    db_dest: str = "/var/lib/postgresql/data",
    db_ro: bool = False,
    image_ref: str = "supabase/postgres:test",
    networks: frozenset[str] | None = None,
) -> c.ApprovedProfileContract:
    bind_src = str((db_bind_src or (deployment / "volumes/db/data")).resolve(strict=False))
    nets = networks if networks is not None else frozenset({f"{cp}_default"})
    services: dict[str, c.ServiceContract] = {}
    for name in c.STANDARD_SERVICES:
        mounts: tuple[c.MountExpectation, ...] = ()
        img = f"example/{name}:1"
        if name == "db":
            mounts = (
                c.MountExpectation("bind", bind_src, db_dest, db_ro),
                c.MountExpectation("volume", f"{cp}_db-config", "/etc/postgresql-custom", False),
            )
            img = image_ref
        services[name] = c.ServiceContract(
            service=name,
            container_name=f"{cp}-{name}",
            image_ref=img,
            mounts=mounts,
            networks=nets,
            required_labels=frozenset(
                {
                    ("io.sbfleet.fleet", fleet),
                    ("io.sbfleet.project", project),
                    ("com.docker.compose.project", cp),
                    ("com.docker.compose.service", name),
                }
            ),
        )
    return c.ApprovedProfileContract(
        compose_project=cp,
        fleet_id=fleet,
        project_id=project,
        services=services,
        expected_network=f"{cp}_default",
        expected_volumes=frozenset({f"{cp}_db-config", f"{cp}_deno-cache"}),
    )


def _db_inspect(
    *,
    cp: str,
    fleet: str,
    project: str,
    deployment: Path,
    mounts: Any = "default",
    networks: Any = "default",
    image_ref: str = "supabase/postgres:test",
    image_id: str = "sha256:" + "1" * 64,
    missing_mounts_key: bool = False,
    null_mounts: bool = False,
    missing_networks: bool = False,
    null_networks: bool = False,
    missing_netsettings: bool = False,
) -> dict[str, Any]:
    bind_src = str((deployment / "volumes/db/data").resolve(strict=False))
    if mounts == "default":
        mounts_val: Any = [
            {
                "Type": "bind",
                "Source": bind_src,
                "Destination": "/var/lib/postgresql/data",
                "RW": True,
                "Mode": "rw",
            },
            {
                "Type": "volume",
                "Name": f"{cp}_db-config",
                "Destination": "/etc/postgresql-custom",
                "RW": True,
            },
        ]
    else:
        mounts_val = mounts
    data: dict[str, Any] = {
        "Id": "c" * 64,
        "Name": f"/{cp}-db",
        "Image": image_id,
        "Config": {
            "Image": image_ref,
            "Labels": {
                "io.sbfleet.fleet": fleet,
                "io.sbfleet.project": project,
                "com.docker.compose.project": cp,
                "com.docker.compose.service": "db",
            },
        },
    }
    if missing_mounts_key:
        pass
    elif null_mounts:
        data["Mounts"] = None
    else:
        data["Mounts"] = mounts_val

    if missing_netsettings:
        pass
    else:
        ns: dict[str, Any] = {}
        if missing_networks:
            pass
        elif null_networks:
            ns["Networks"] = None
        elif networks == "default":
            ns["Networks"] = {f"{cp}_default": {"NetworkID": "a" * 64}}
        else:
            ns["Networks"] = networks
        data["NetworkSettings"] = ns
    return data


class _Obs:
    def __init__(self, state: str, data: dict | None = None, detail: str = "") -> None:
        self.state = state
        self.data = data
        self.detail = detail


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _patch_invent(
    monkeypatch: pytest.MonkeyPatch, *, container_data: dict | None, list_fail: bool = False
):
    if list_fail:
        failed = _Obs("FAILED", detail="cannot talk to docker")
        monkeypatch.setattr(auth, "_docker_ps_filter_ids", lambda *_a, **_k: failed)
        monkeypatch.setattr(auth, "_docker_network_ls_ids", lambda *_a, **_k: failed)
        monkeypatch.setattr(auth, "_docker_volume_ls_names", lambda *_a, **_k: failed)
        return

    def ps(_f):
        if container_data is None:
            return _Obs("PRESENT", {"ids": []})
        return _Obs("PRESENT", {"ids": ["c" * 64]})

    def inspect(args):
        if args[0] == "inspect" and container_data is not None:
            return _Obs("PRESENT", container_data)
        return _Obs("ABSENT")

    monkeypatch.setattr(auth, "_docker_ps_filter_ids", ps)
    monkeypatch.setattr(auth, "_docker_inspect_observation", inspect)
    monkeypatch.setattr(
        auth, "_docker_network_ls_ids", lambda *_a, **_k: _Obs("PRESENT", {"ids": []})
    )
    monkeypatch.setattr(
        auth, "_docker_volume_ls_names", lambda *_a, **_k: _Obs("PRESENT", {"names": []})
    )


def test_missing_mounts_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep, missing_mounts_key=True)
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="missing Mounts"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_null_mounts_refuses(home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep, null_mounts=True)
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="null Mounts"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_missing_networksettings_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(cp=cp, fleet=fleet, project=proj, deployment=dep, missing_netsettings=True)
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="NetworkSettings"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_expected_plus_foreign_network_refuses(
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
        networks={
            f"{cp}_default": {"NetworkID": "a" * 64},
            "foreign_net": {"NetworkID": "b" * 64},
        },
    )
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="network attachment set mismatch"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_wrong_bind_destination_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    bind_src = str((dep / "volumes/db/data").resolve(strict=False))
    data = _db_inspect(
        cp=cp,
        fleet=fleet,
        project=proj,
        deployment=dep,
        mounts=[
            {
                "Type": "bind",
                "Source": bind_src,
                "Destination": "/wrong/dest",
                "RW": True,
            },
            {
                "Type": "volume",
                "Name": f"{cp}_db-config",
                "Destination": "/etc/postgresql-custom",
                "RW": True,
            },
        ],
    )
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="mount contract mismatch"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_wrong_bind_source_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    other = tmp_path / "other/data"
    other.mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(
        cp=cp,
        fleet=fleet,
        project=proj,
        deployment=dep,
        mounts=[
            {
                "Type": "bind",
                "Source": str(other.resolve()),
                "Destination": "/var/lib/postgresql/data",
                "RW": True,
            },
            {
                "Type": "volume",
                "Name": f"{cp}_db-config",
                "Destination": "/etc/postgresql-custom",
                "RW": True,
            },
        ],
    )
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="mount contract mismatch"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_wrong_mount_mode_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    bind_src = str((dep / "volumes/db/data").resolve(strict=False))
    data = _db_inspect(
        cp=cp,
        fleet=fleet,
        project=proj,
        deployment=dep,
        mounts=[
            {
                "Type": "bind",
                "Source": bind_src,
                "Destination": "/var/lib/postgresql/data",
                "RW": False,
                "Mode": "ro",
            },
            {
                "Type": "volume",
                "Name": f"{cp}_db-config",
                "Destination": "/etc/postgresql-custom",
                "RW": True,
            },
        ],
    )
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep, db_ro=False)
    with pytest.raises(auth.AuthorityError, match="mount contract mismatch"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_wrong_image_reference_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(
        cp=cp, fleet=fleet, project=proj, deployment=dep, image_ref="evil/postgres:latest"
    )
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="Config.Image reference mismatch"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_wrong_runtime_image_id_refuses_when_recorded(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    data = _db_inspect(
        cp=cp, fleet=fleet, project=proj, deployment=dep, image_id="sha256:" + "2" * 64
    )
    _patch_invent(monkeypatch, container_data=data)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="runtime image identity mismatch"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
            recorded_image_ids={"db": "sha256:" + "1" * 64},
        )


def test_expected_name_only_copied_labels_insufficient(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Name path with fleet labels but wrong mounts must not authorize."""
    dep = tmp_path / "dep"
    (dep / "volumes/db/data").mkdir(parents=True)
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    # Label list empty; expected-name probe finds container with labels but empty mounts.
    data = {
        "Id": "d" * 64,
        "Name": f"/{cp}-db",
        "Image": "sha256:" + "1" * 64,
        "Config": {
            "Image": "supabase/postgres:test",
            "Labels": {
                "io.sbfleet.fleet": fleet,
                "io.sbfleet.project": proj,
                "com.docker.compose.project": cp,
                "com.docker.compose.service": "db",
            },
        },
        "Mounts": [],
        "NetworkSettings": {"Networks": {f"{cp}_default": {}}},
    }

    def ps(_f):
        return _Obs("PRESENT", {"ids": []})

    def inspect(args):
        target = args[-1]
        if target == f"{cp}-db" or target.endswith("-db"):
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
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="expected-name-conflict|mount contract"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_malformed_inspect_refuses(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    dep.mkdir()
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    monkeypatch.setattr(
        auth, "_docker_ps_filter_ids", lambda *_a, **_k: _Obs("PRESENT", {"ids": ["x"]})
    )
    monkeypatch.setattr(
        auth,
        "_docker_inspect_observation",
        lambda *_a, **_k: _Obs("FAILED", detail="invalid character"),
    )
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="FAILED|unproven"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )


def test_docker_failure_refuses_zero_mutate(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dep = tmp_path / "dep"
    dep.mkdir()
    cp, fleet, proj = "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb", "a" * 32, "b" * 32
    mutate = mock.Mock()
    _patch_invent(monkeypatch, container_data=None, list_fail=True)
    monkeypatch.setattr(auth, "run", mutate)
    contract = _contract(cp=cp, fleet=fleet, project=proj, deployment=dep)
    with pytest.raises(auth.AuthorityError, match="FAILED|cannot talk"):
        auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet,
            project_id=proj,
            deployment=dep,
            contract=contract,
        )
    # invent uses observation helpers; ensure no accidental mutate argv with rm/stop
    for call in mutate.call_args_list:
        argv = call.args[0] if call.args else []
        assert "rm" not in argv and "stop" not in argv and "kill" not in argv


def test_normal_reviewed_container_passes(
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
    assert inv.containers[0].resource_id == "c" * 64
