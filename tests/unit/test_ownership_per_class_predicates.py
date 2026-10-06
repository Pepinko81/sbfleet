"""Ownership per class predicates."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sbfleet.cli import EXIT_SAFETY
from sbfleet.sandbox import sandbox_cmd
from sbfleet.sandbox_adoption import (
    SandboxLocks,
    commit_adoption_pair,
    new_adoption,
)
from sbfleet.sandbox_authority import (
    ClassObservation,
    SandboxAuthorityError,
    SandboxLiveAuthority,
    require_action_live_authority,
)


def _ns(**kwargs):  # noqa: ANN003
    base = {
        "action": "destroy",
        "path": "/tmp/x",
        "yes": True,
        "revalidate": False,
        "migration_mode": None,
        "cmd": [],
        "json": False,
        "home": None,
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_reset_absent_containers_refuse() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="CONFIRMED_ABSENT"),
        network=ClassObservation(status="PRESENT_AND_OWNED", ids=["n1"]),
        volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["v1"]),
    )
    with pytest.raises(SandboxAuthorityError, match="reset requires PRESENT_AND_OWNED containers"):
        require_action_live_authority("reset", live)


def test_env_absent_no_spawn_predicate() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="CONFIRMED_ABSENT"),
        network=ClassObservation(status="CONFIRMED_ABSENT"),
        volumes=ClassObservation(status="CONFIRMED_ABSENT"),
    )
    with pytest.raises(SandboxAuthorityError, match="env requires"):
        require_action_live_authority("env", live)


def test_destroy_unknown_inventory_refuses_not_fallback() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="UNKNOWN", detail="inspect failed"),
        network=ClassObservation(status="PRESENT_AND_OWNED", ids=["n1"]),
        volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["stale-vol"]),
    )
    with pytest.raises(SandboxAuthorityError, match="UNKNOWN/foreign"):
        require_action_live_authority("destroy", live)


def test_mixed_foreign_volume_not_hidden_by_absent_containers() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="CONFIRMED_ABSENT"),
        network=ClassObservation(status="CONFIRMED_ABSENT"),
        volumes=ClassObservation(status="PRESENT_BUT_FOREIGN", names=["evil"]),
    )
    with pytest.raises(SandboxAuthorityError, match="FOREIGN|foreign"):
        require_action_live_authority("destroy", live)
    with pytest.raises(SandboxAuthorityError, match="FOREIGN|foreign"):
        require_action_live_authority("stop", live)


def test_stop_idempotent_when_containers_absent() -> None:
    live = SandboxLiveAuthority(
        containers=ClassObservation(status="CONFIRMED_ABSENT"),
        network=ClassObservation(status="CONFIRMED_ABSENT"),
        volumes=ClassObservation(status="CONFIRMED_ABSENT"),
    )
    require_action_live_authority("stop", live)


def test_destroy_handler_refuses_on_failed_live_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    (app / "supabase").mkdir(parents=True)
    (app / "supabase" / "config.toml").write_text(
        'project_id = "sbfleet-test-destr1"\n[api]\nport = 54321\n[db]\nport = 54322\n',
        encoding="utf-8",
    )
    rec = new_adoption(
        canonical=app.resolve(),
        cli_project_id="sbfleet-test-destr1",
        config_fingerprint="",
        fingerprint_fields={"project_id": "sbfleet-test-destr1"},
        cli_version="2.118.0",
        migration_mode="supabase",
        network_id="netdeadbeef",
        owned_resources={"volumes": [{"name": "stale-cached-vol"}]},
    )
    # Fix fingerprint to match parsed config
    from sbfleet.sandbox_config import parse_sandbox_config

    cfg = parse_sandbox_config(app.resolve())
    rec = new_adoption(
        canonical=app.resolve(),
        cli_project_id=cfg.project_id,
        config_fingerprint=cfg.fingerprint,
        fingerprint_fields=cfg.fingerprint_fields,
        cli_version="2.118.0",
        migration_mode="supabase",
        network_id="netdeadbeef",
        owned_resources={"volumes": [{"name": "stale-cached-vol"}]},
    )
    with SandboxLocks(home, app.resolve()):
        commit_adoption_pair(home, rec)

    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        dispatched.append(list(argv))
        return MagicMock(ok=True, stdout="", stderr="", returncode=0)

    monkeypatch.setattr("sbfleet.sandbox.run", fake_run)
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(status="UNKNOWN", detail="invent failed"),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["netdeadbeef"]),
            volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["stale-cached-vol"]),
        ),
    )

    args = _ns(action="destroy", path=str(app), yes=True, home=str(home))
    code = sandbox_cmd(args)
    assert code == EXIT_SAFETY
    # Must not dispatch stop --no-backup or volume rm using cached names.
    assert not any("stop" in a for a in dispatched)
    assert not any(a[:3] == ["docker", "volume", "rm"] for a in dispatched)
