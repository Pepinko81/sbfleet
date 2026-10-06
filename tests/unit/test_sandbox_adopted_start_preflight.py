"""Sandbox adopted start preflight."""

from __future__ import annotations

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
    attempt_delta_owned,
    require_action_live_authority,
    snapshot_positively_owned,
)
from sbfleet.sandbox_config import parse_sandbox_config


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


def _seed_adopted(
    tmp_path: Path, *, network_id: str = "netpreexist01"
) -> tuple[Path, Path, object]:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    (app / "supabase").mkdir(parents=True)
    (app / "supabase" / "config.toml").write_text(
        'project_id = "sbfleet-test-v3c05"\n[api]\nport = 54321\n[db]\nport = 54322\n',
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
    with SandboxLocks(home, app.resolve()):
        commit_adoption_pair(home, rec)
    return home, app, rec


def _absent_owned_live(*, network_id: str = "netpreexist01", volumes: list[str] | None = None):
    return SandboxLiveAuthority(
        containers=ClassObservation(status="CONFIRMED_ABSENT", detail="no CLI containers"),
        network=ClassObservation(
            status="PRESENT_AND_OWNED", detail="network owned", ids=[network_id]
        ),
        volumes=ClassObservation(
            status="PRESENT_AND_OWNED" if volumes else "CONFIRMED_ABSENT",
            names=list(volumes or []),
            detail="volumes",
        ),
    )


def test_start_predicate_foreign_container_refuses() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(
            status="PRESENT_BUT_FOREIGN", detail="copied labels", ids=["c1"]
        ),
        network=ClassObservation(status="PRESENT_AND_OWNED", ids=["n1"]),
        volumes=ClassObservation(status="CONFIRMED_ABSENT"),
    )
    with pytest.raises(SandboxAuthorityError, match="UNKNOWN/foreign"):
        require_action_live_authority("start", live)


def test_start_predicate_unknown_network_refuses() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="CONFIRMED_ABSENT"),
        network=ClassObservation(status="UNKNOWN", detail="inspect failed"),
        volumes=ClassObservation(status="CONFIRMED_ABSENT"),
    )
    with pytest.raises(SandboxAuthorityError, match="UNKNOWN/foreign"):
        require_action_live_authority("start", live)


def test_start_predicate_foreign_volume_refuses() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="CONFIRMED_ABSENT"),
        network=ClassObservation(status="PRESENT_AND_OWNED", ids=["n1"]),
        volumes=ClassObservation(status="PRESENT_BUT_FOREIGN", names=["evil"]),
    )
    with pytest.raises(SandboxAuthorityError, match="FOREIGN|foreign"):
        require_action_live_authority("start", live)


def test_start_predicate_stopped_owned_allows() -> None:
    live = _absent_owned_live(volumes=["vol-pre-owned"])
    require_action_live_authority("start", live)


def test_attempt_delta_excludes_preexisting() -> None:
    pre = {
        "containers": set(),
        "volumes": {"vol-pre-owned"},
        "networks": {"netpreexist01"},
    }
    post = SandboxLiveAuthority(
        containers=ClassObservation(
            status="PRESENT_AND_OWNED", ids=["newctr01"], names=["supabase_db_x"]
        ),
        network=ClassObservation(status="PRESENT_AND_OWNED", ids=["netpreexist01"]),
        volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["vol-pre-owned", "vol-new"]),
    )
    delta = attempt_delta_owned(pre, post)
    assert delta["containers"] == {"newctr01"}
    assert delta["volumes"] == {"vol-new"}
    assert delta["networks"] == set()
    assert "netpreexist01" not in delta["networks"]
    assert "vol-pre-owned" not in delta["volumes"]


def test_adopted_start_foreign_container_zero_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, app, _rec = _seed_adopted(tmp_path)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        dispatched.append(list(argv))
        return MagicMock(ok=True, stdout="", stderr="", returncode=0)

    monkeypatch.setattr("sbfleet.sandbox.run", fake_run)
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(
                status="PRESENT_BUT_FOREIGN", detail="foreign", ids=["foreignctr"]
            ),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["netpreexist01"]),
            volumes=ClassObservation(status="CONFIRMED_ABSENT"),
        ),
    )
    code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_SAFETY
    assert not any("start" in a and "supabase" in a[0] for a in dispatched)
    assert not any("stop" in a for a in dispatched)
    assert (app / "src" / "marker.txt").read_text(encoding="utf-8") == "app-source-keep"


def test_adopted_start_unknown_inspect_zero_dispatch(
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
            containers=ClassObservation(status="UNKNOWN", detail="missing inspect field"),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["netpreexist01"]),
            volumes=ClassObservation(status="CONFIRMED_ABSENT"),
        ),
    )
    code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_SAFETY
    assert not any(a and a[0] == "supabase" and "start" in a for a in dispatched)


def test_postflight_failure_attempt_delta_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pre-existing owned net/vol survive; new owned container cleaned by exact ID.

    No stop --project-id.
    """
    home, app, _rec = _seed_adopted(tmp_path)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []
    observe_calls = {"n": 0}

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        dispatched.append(list(argv))
        return MagicMock(ok=True, stdout="ok", stderr="", returncode=0)

    def fake_observe(*_a, **_k):  # noqa: ANN002, ANN003
        observe_calls["n"] += 1
        if observe_calls["n"] == 1:
            return _absent_owned_live(volumes=["vol-pre-owned"])
        # Post-start: pre-existing owned + new owned container + foreign volume untouched class
        return SandboxLiveAuthority(
            containers=ClassObservation(
                status="PRESENT_AND_OWNED", ids=["newctrdeadbeef"], names=["db"]
            ),
            network=ClassObservation(
                status="PRESENT_AND_OWNED", ids=["netpreexist01"], names=["sb-net"]
            ),
            volumes=ClassObservation(
                status="PRESENT_AND_OWNED", names=["vol-pre-owned", "vol-new-owned"]
            ),
        )

    monkeypatch.setattr("sbfleet.sandbox.run", fake_run)
    monkeypatch.setattr("sbfleet.sandbox_authority.run", fake_run)
    monkeypatch.setattr("sbfleet.sandbox.observe_sandbox_live", fake_observe)
    monkeypatch.setattr("sbfleet.sandbox.ensure_owned_network", lambda adoption: "netpreexist01")
    monkeypatch.setattr("sbfleet.sandbox.prove_network_owned", lambda *a, **k: {})
    monkeypatch.setattr(
        "sbfleet.sandbox.invent_owned_resources",
        lambda **kwargs: (_ for _ in ()).throw(
            SandboxAuthorityError("post-start binding/ownership failed")
        ),
    )

    sentinel_before = {"net": "net-sentinel", "vol": "vol-sentinel", "ctr": "ctr-sentinel"}
    code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_SAFETY
    # Official CLI start happened once.
    assert any(a and a[0] == "supabase" and "start" in a for a in dispatched)
    # No broad stop --project-id
    assert not any(
        "stop" in a and "--project-id" in a for a in dispatched if a and a[0] == "supabase"
    )
    # New container exact-ID cleanup
    assert any(
        a[:3] == ["docker", "stop", "--"] and "newctrdeadbeef" in a for a in dispatched
    ) or any(a[:3] == ["docker", "rm", "-f"] and "newctrdeadbeef" in a for a in dispatched)
    # Pre-existing network must not be removed
    assert not any(
        a[:3] == ["docker", "network", "rm"] and "netpreexist01" in a for a in dispatched
    )
    # Pre-existing volume must not be removed
    assert not any(a[:3] == ["docker", "volume", "rm"] and "vol-pre-owned" in a for a in dispatched)
    # New owned volume may be cleaned
    assert any(a[:3] == ["docker", "volume", "rm"] and "vol-new-owned" in a for a in dispatched)
    # App source preserved
    assert (app / "src" / "marker.txt").read_text(encoding="utf-8") == "app-source-keep"
    # Sentinels conceptual: never targeted
    assert not any(sentinel_before["net"] in " ".join(a) for a in dispatched)
    assert not any(sentinel_before["vol"] in " ".join(a) for a in dispatched)
    assert not any(sentinel_before["ctr"] in " ".join(a) for a in dispatched)


def test_postflight_foreign_resource_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, app, _rec = _seed_adopted(tmp_path)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []
    observe_calls = {"n": 0}

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        dispatched.append(list(argv))
        return MagicMock(ok=True, stdout="ok", stderr="", returncode=0)

    def fake_observe(*_a, **_k):  # noqa: ANN002, ANN003
        observe_calls["n"] += 1
        if observe_calls["n"] == 1:
            return _absent_owned_live()
        return SandboxLiveAuthority(
            containers=ClassObservation(
                status="PRESENT_BUT_FOREIGN", detail="foreign after start", ids=["foreignctr99"]
            ),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["netpreexist01"]),
            volumes=ClassObservation(status="UNKNOWN", detail="inspect failed"),
        )

    monkeypatch.setattr("sbfleet.sandbox.run", fake_run)
    monkeypatch.setattr("sbfleet.sandbox_authority.run", fake_run)
    monkeypatch.setattr("sbfleet.sandbox.observe_sandbox_live", fake_observe)
    monkeypatch.setattr("sbfleet.sandbox.ensure_owned_network", lambda adoption: "netpreexist01")
    monkeypatch.setattr("sbfleet.sandbox.prove_network_owned", lambda *a, **k: {})
    monkeypatch.setattr(
        "sbfleet.sandbox.invent_owned_resources",
        lambda **kwargs: (_ for _ in ()).throw(SandboxAuthorityError("foreign invent")),
    )
    code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_SAFETY
    assert not any("foreignctr99" in " ".join(a) for a in dispatched)
    assert not any(
        "stop" in a and "--project-id" in a for a in dispatched if a and a[0] == "supabase"
    )


def test_already_running_owned_idempotent_no_second_start(
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
    inv = {
        "containers": [{"id": "c1", "name": "db"}],
        "volumes": [],
        "network_id": "netpreexist01",
        "published_bindings": [],
    }
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(status="PRESENT_AND_OWNED", ids=["c1"], runtime="RUNNING"),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["netpreexist01"]),
            volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["vol-pre-owned"]),
            inventory=inv,
        ),
    )
    monkeypatch.setattr("sbfleet.sandbox.assert_effective_bindings", lambda *_a, **_k: None)
    code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    assert code == EXIT_OK
    assert not any(a and a[0] == "supabase" and "start" in a for a in dispatched)


def test_snapshot_positively_owned_ignores_foreign() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="PRESENT_BUT_FOREIGN", ids=["x"]),
        network=ClassObservation(status="PRESENT_AND_OWNED", ids=["n1"]),
        volumes=ClassObservation(status="UNKNOWN", names=["v1"]),
    )
    snap = snapshot_positively_owned(live)
    assert snap["containers"] == set()
    assert snap["networks"] == {"n1"}
    assert snap["volumes"] == set()
