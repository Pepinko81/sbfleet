"""Sandbox attachment state."""

from __future__ import annotations

import io
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sbfleet.cli import EXIT_OK, EXIT_SAFETY
from sbfleet.sandbox import sandbox_cmd
from sbfleet.sandbox_adoption import SandboxLocks, commit_adoption_pair, new_adoption
from sbfleet.sandbox_authority import (
    ClassObservation,
    SandboxAuthorityError,
    SandboxLiveAuthority,
    _observe_containers,
    invent_owned_resources,
    require_action_live_authority,
)
from sbfleet.sandbox_config import parse_sandbox_config

NET_ID = "a" * 64
NET_NAME = "sbfleet-sb-testhash01"
NET_SHORT = "a" * 12
NET_COLLIDING = ("a" * 12) + ("b" * 52)


def _ns(**kwargs):  # noqa: ANN003
    base = {
        "action": "start",
        "path": "/tmp/x",
        "yes": False,
        "revalidate": False,
        "migration_mode": None,
        "cmd": [],
        "json": False,
        "home": None,
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def _seed_adopted(tmp_path: Path, *, network_id: str = NET_ID) -> tuple[Path, Path, object]:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    (app / "supabase").mkdir(parents=True)
    (app / "supabase" / "config.toml").write_text(
        'project_id = "sbfleet-test-v4003"\n[api]\nport = 54321\n[db]\nport = 54322\n',
        encoding="utf-8",
    )
    (app / "src").mkdir()
    (app / "src" / "marker.txt").write_text("app-source-keep", encoding="utf-8")
    cfg = parse_sandbox_config(app.resolve())
    rec = new_adoption(
        canonical=app.resolve(),
        cli_project_id=cfg.project_id,
        config_fingerprint=cfg.fingerprint,
        fingerprint_fields=cfg.fingerprint_fields,
        cli_version="2.118.0",
        migration_mode="supabase",
        network_id=network_id,
        owned_resources={"volumes": [{"name": "vol-pre-owned"}], "containers": []},
    )
    # Force predictable network_name for attachment proof.
    from sbfleet.sandbox_adoption import update_record_fields

    rec = update_record_fields(rec, network_name=NET_NAME)
    with SandboxLocks(home, app.resolve()):
        commit_adoption_pair(home, rec)
    return home, app, rec


def _owned_inspect(
    *,
    project_id: str,
    workdir: str,
    network_name: str = NET_NAME,
    network_id: str = NET_ID,
    running: bool = True,
    status: str = "running",
    extra_nets: dict | None = None,
    cid: str = "c" * 64,
) -> dict:
    nets = {network_name: {"NetworkID": network_id}}
    if extra_nets:
        nets.update(extra_nets)
    return {
        "Id": cid,
        "Name": "/supabase_db_x",
        "Config": {
            "Labels": {
                "com.supabase.cli.project": project_id,
                "com.supabase.cli.workdir": workdir,
            }
        },
        "State": {"Running": running, "Status": status},
        "NetworkSettings": {
            "Networks": nets,
            "Ports": {"54321/tcp": [{"HostIp": "127.0.0.1", "HostPort": "54321"}]},
        },
    }


def test_owned_running_idempotent_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, app, rec = _seed_adopted(tmp_path)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda argv, **kwargs: (
            dispatched.append(list(argv)) or MagicMock(ok=True, stdout="", stderr="", returncode=0)
        ),
    )
    inv = {
        "containers": [{"id": "c1", "name": "db"}],
        "volumes": [],
        "network_id": NET_ID,
        "network_name": NET_NAME,
        "published_bindings": [
            {
                "container_id": "c1",
                "port": "54321/tcp",
                "host_ip": "127.0.0.1",
                "host_port": "54321",
            }
        ],
    }
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(status="PRESENT_AND_OWNED", ids=["c1"], runtime="RUNNING"),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=[NET_ID]),
            volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["vol-pre-owned"]),
            inventory=inv,
        ),
    )
    monkeypatch.setattr("sbfleet.sandbox.assert_effective_bindings", lambda *_a, **_k: None)
    out = io.StringIO()
    err = io.StringIO()
    from contextlib import redirect_stdout

    with redirect_stdout(out), redirect_stderr(err):
        code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_OK
    assert not any(a and a[0] == "supabase" and "start" in a for a in dispatched)
    assert "already running" in out.getvalue()


def test_cold_absent_dispatches_guarded_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, app, _rec = _seed_adopted(tmp_path)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        dispatched.append(list(argv))
        return MagicMock(ok=True, stdout="ok", stderr="", returncode=0)

    monkeypatch.setattr("sbfleet.sandbox.run", fake_run)
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(
                status="CONFIRMED_ABSENT", detail="no CLI containers", runtime="ABSENT"
            ),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=[NET_ID]),
            volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["vol-pre-owned"]),
        ),
    )
    monkeypatch.setattr("sbfleet.sandbox.ensure_owned_network", lambda adoption: NET_ID)
    monkeypatch.setattr("sbfleet.sandbox.prove_network_owned", lambda *a, **k: {})
    monkeypatch.setattr(
        "sbfleet.sandbox.invent_owned_resources",
        lambda **kwargs: {
            "containers": [{"id": "new1"}],
            "volumes": [],
            "network_id": NET_ID,
            "network_name": NET_NAME,
            "published_bindings": [
                {
                    "container_id": "new1",
                    "port": "54321/tcp",
                    "host_ip": "127.0.0.1",
                    "host_port": "54321",
                }
            ],
        },
    )
    monkeypatch.setattr("sbfleet.sandbox.assert_effective_bindings", lambda *_a, **_k: None)
    code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_OK
    assert any(a and a[0] == "supabase" and "start" in a for a in dispatched)


def test_retained_exited_refuses_not_already_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, app, _rec = _seed_adopted(tmp_path)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda argv, **kwargs: (
            dispatched.append(list(argv)) or MagicMock(ok=True, stdout="", stderr="", returncode=0)
        ),
    )
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(
                status="PRESENT_AND_OWNED",
                ids=["c1"],
                runtime="STOPPED",
                detail="exited retained",
            ),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=[NET_ID]),
            volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["vol-pre-owned"]),
        ),
    )
    err = io.StringIO()
    with redirect_stderr(err):
        code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    text = err.getvalue()
    assert code == EXIT_SAFETY
    assert "already running" not in text.lower()
    assert not any(a and a[0] == "supabase" and "start" in a for a in dispatched)


def test_mixed_running_exited_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, app, _rec = _seed_adopted(tmp_path)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda argv, **kwargs: (
            dispatched.append(list(argv)) or MagicMock(ok=True, stdout="", stderr="", returncode=0)
        ),
    )
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(
                status="PRESENT_AND_OWNED",
                ids=["c1", "c2"],
                runtime="MIXED",
                detail="mixed RUNNING/EXITED",
            ),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=[NET_ID]),
            volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["vol-pre-owned"]),
        ),
    )
    err = io.StringIO()
    with redirect_stderr(err):
        code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_SAFETY
    assert "already running" not in err.getvalue().lower()
    assert not any(a and a[0] == "supabase" and "start" in a for a in dispatched)


def test_foreign_network_refuses_zero_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, app, rec = _seed_adopted(tmp_path)
    project_id = rec.cli_project_id
    workdir = str(app.resolve())
    obj = _owned_inspect(
        project_id=project_id,
        workdir=workdir,
        extra_nets={"foreign_network": {"NetworkID": "f" * 64}},
    )
    monkeypatch.setattr(
        "sbfleet.sandbox_authority.list_cli_containers", lambda *_a, **_k: [obj["Id"]]
    )
    monkeypatch.setattr("sbfleet.sandbox_authority._docker_json", lambda *_a, **_k: [obj])
    obs = _observe_containers(
        project_id=project_id,
        canonical_root=app.resolve(),
        network_id=NET_ID,
        network_name=NET_NAME,
    )
    assert obs.status == "PRESENT_BUT_FOREIGN"

    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda argv, **kwargs: (
            dispatched.append(list(argv)) or MagicMock(ok=True, stdout="", stderr="", returncode=0)
        ),
    )
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=obs,
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=[NET_ID]),
            volumes=ClassObservation(status="CONFIRMED_ABSENT"),
        ),
    )
    code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_SAFETY
    assert not any(a and a[0] == "supabase" and "start" in a for a in dispatched)


def test_expected_name_wrong_network_id_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    project_id = "sbfleet-test-v4003"
    obj = _owned_inspect(
        project_id=project_id,
        workdir=str(app.resolve()),
        network_id="b" * 64,
    )
    monkeypatch.setattr(
        "sbfleet.sandbox_authority.list_cli_containers", lambda *_a, **_k: [obj["Id"]]
    )
    monkeypatch.setattr("sbfleet.sandbox_authority.list_cli_volumes", lambda *_a, **_k: [])
    monkeypatch.setattr("sbfleet.sandbox_authority._docker_json", lambda *_a, **_k: [obj])
    with pytest.raises(SandboxAuthorityError, match="NetworkID mismatch"):
        invent_owned_resources(
            project_id=project_id,
            canonical_root=app.resolve(),
            network_id=NET_ID,
            network_name=NET_NAME,
        )


def test_matching_id_under_unexpected_name_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    project_id = "sbfleet-test-v4003"
    obj = {
        "Id": "c" * 64,
        "Name": "/supabase_db_x",
        "Config": {
            "Labels": {
                "com.supabase.cli.project": project_id,
                "com.supabase.cli.workdir": str(app.resolve()),
            }
        },
        "NetworkSettings": {
            "Networks": {"foreign_name": {"NetworkID": NET_ID}},
            "Ports": {"54321/tcp": [{"HostIp": "127.0.0.1", "HostPort": "54321"}]},
        },
    }
    monkeypatch.setattr(
        "sbfleet.sandbox_authority.list_cli_containers", lambda *_a, **_k: [obj["Id"]]
    )
    monkeypatch.setattr("sbfleet.sandbox_authority.list_cli_volumes", lambda *_a, **_k: [])
    monkeypatch.setattr("sbfleet.sandbox_authority._docker_json", lambda *_a, **_k: [obj])
    with pytest.raises(SandboxAuthorityError, match="attachment set mismatch|unexpected"):
        invent_owned_resources(
            project_id=project_id,
            canonical_root=app.resolve(),
            network_id=NET_ID,
            network_name=NET_NAME,
        )


def test_null_attachment_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = tmp_path / "app"
    app.mkdir()
    project_id = "sbfleet-test-v4003"
    obj = _owned_inspect(project_id=project_id, workdir=str(app.resolve()))
    obj["NetworkSettings"]["Networks"] = {NET_NAME: None}
    monkeypatch.setattr(
        "sbfleet.sandbox_authority.list_cli_containers", lambda *_a, **_k: [obj["Id"]]
    )
    monkeypatch.setattr("sbfleet.sandbox_authority.list_cli_volumes", lambda *_a, **_k: [])
    monkeypatch.setattr("sbfleet.sandbox_authority._docker_json", lambda *_a, **_k: [obj])
    with pytest.raises(SandboxAuthorityError, match="null/malformed"):
        invent_owned_resources(
            project_id=project_id,
            canonical_root=app.resolve(),
            network_id=NET_ID,
            network_name=NET_NAME,
        )


def test_unknown_inspect_refuses_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, app, _rec = _seed_adopted(tmp_path)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda argv, **kwargs: (
            dispatched.append(list(argv)) or MagicMock(ok=True, stdout="", stderr="", returncode=0)
        ),
    )
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(
                status="UNKNOWN", detail="inspect failed", runtime="UNKNOWN"
            ),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=[NET_ID]),
            volumes=ClassObservation(status="CONFIRMED_ABSENT"),
        ),
    )
    code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_SAFETY
    assert not any(a and a[0] == "supabase" and "start" in a for a in dispatched)


def test_start_predicate_exited_refuses() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="PRESENT_AND_OWNED", ids=["c1"], runtime="STOPPED"),
        network=ClassObservation(status="PRESENT_AND_OWNED", ids=[NET_ID]),
        volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["v1"]),
    )
    with pytest.raises(SandboxAuthorityError, match="non-running|runtime"):
        require_action_live_authority("start", live)


def test_one_char_attachment_network_id_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: attachment 'a' vs owned 'a'*64 must refuse (no prefix authority)."""
    app = tmp_path / "app"
    app.mkdir()
    project_id = "sbfleet-test-v4003"
    obj = _owned_inspect(
        project_id=project_id,
        workdir=str(app.resolve()),
        network_id="a",
    )
    monkeypatch.setattr(
        "sbfleet.sandbox_authority.list_cli_containers", lambda *_a, **_k: [obj["Id"]]
    )
    monkeypatch.setattr("sbfleet.sandbox_authority.list_cli_volumes", lambda *_a, **_k: [])
    monkeypatch.setattr("sbfleet.sandbox_authority._docker_json", lambda *_a, **_k: [obj])
    with pytest.raises(SandboxAuthorityError, match="malformed|NetworkID|mismatch"):
        invent_owned_resources(
            project_id=project_id,
            canonical_root=app.resolve(),
            network_id=NET_ID,
            network_name=NET_NAME,
        )


def test_colliding_short_prefix_attachment_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stored short 'a'*12 resolves to 'a'*64; attachment 'a'*12+'b'*52 must refuse."""
    app = tmp_path / "app"
    app.mkdir()
    project_id = "sbfleet-test-v4003"
    obj = _owned_inspect(
        project_id=project_id,
        workdir=str(app.resolve()),
        network_id=NET_COLLIDING,
    )
    monkeypatch.setattr(
        "sbfleet.sandbox_authority.list_cli_containers", lambda *_a, **_k: [obj["Id"]]
    )
    monkeypatch.setattr("sbfleet.sandbox_authority.list_cli_volumes", lambda *_a, **_k: [])
    monkeypatch.setattr("sbfleet.sandbox_authority._docker_json", lambda *_a, **_k: [obj])
    with pytest.raises(SandboxAuthorityError, match="NetworkID mismatch"):
        invent_owned_resources(
            project_id=project_id,
            canonical_root=app.resolve(),
            network_id=NET_ID,
            network_name=NET_NAME,
        )


def test_non_string_attachment_network_id_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    project_id = "sbfleet-test-v4003"
    obj = _owned_inspect(project_id=project_id, workdir=str(app.resolve()))
    obj["NetworkSettings"]["Networks"] = {NET_NAME: {"NetworkID": 42}}
    monkeypatch.setattr(
        "sbfleet.sandbox_authority.list_cli_containers", lambda *_a, **_k: [obj["Id"]]
    )
    monkeypatch.setattr("sbfleet.sandbox_authority.list_cli_volumes", lambda *_a, **_k: [])
    monkeypatch.setattr("sbfleet.sandbox_authority._docker_json", lambda *_a, **_k: [obj])
    with pytest.raises(SandboxAuthorityError, match="must be string|malformed"):
        invent_owned_resources(
            project_id=project_id,
            canonical_root=app.resolve(),
            network_id=NET_ID,
            network_name=NET_NAME,
        )


def test_stored_short_resolves_canonical_attachment_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Legitimate short stored ID that resolves; attachment equals canonical full Id."""
    from sbfleet.sandbox_authority import _canonical_network_id_from_inspect

    canonical = _canonical_network_id_from_inspect({"Id": NET_ID}, stored_ref=NET_SHORT)
    assert canonical == NET_ID
    app = tmp_path / "app"
    app.mkdir()
    project_id = "sbfleet-test-v4003"
    obj = _owned_inspect(
        project_id=project_id,
        workdir=str(app.resolve()),
        network_id=NET_ID,
    )
    monkeypatch.setattr(
        "sbfleet.sandbox_authority.list_cli_containers", lambda *_a, **_k: [obj["Id"]]
    )
    monkeypatch.setattr("sbfleet.sandbox_authority.list_cli_volumes", lambda *_a, **_k: [])
    monkeypatch.setattr("sbfleet.sandbox_authority._docker_json", lambda *_a, **_k: [obj])
    inv = invent_owned_resources(
        project_id=project_id,
        canonical_root=app.resolve(),
        network_id=NET_ID,
        network_name=NET_NAME,
    )
    assert len(inv["containers"]) == 1
    assert inv["network_id"] == NET_ID
