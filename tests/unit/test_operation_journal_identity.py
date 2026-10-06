"""Operation journal identity."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import authority as auth
from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet import update as upd
from sbfleet.process import ProcessResult
from sbfleet.projects import stop_project


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed(home: Path, slug: str = "alpha") -> dict:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    cp = reg.compose_project_name(fid, pid)
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": cp,
        "ports": {
            "gateway": 21010,
            "db_direct": 21011,
            "pooler_session": 21012,
            "pooler_transaction": 21013,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:21010",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "a" * 40},
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": True,
    }
    reg.write_project(home, meta)
    pdir = reg.project_dir(home, slug)
    dep = pdir / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(dep / "run.sh", 0o700)
    (dep / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    c.write_override(
        dep,
        c.render_override(
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            gateway_port=21010,
            db_direct_port=21011,
            pooler_session_port=21012,
            pooler_transaction_port=21013,
        ),
    )
    (dep / ".env").write_text(
        "\n".join(
            [
                f"COMPOSE_PROJECT_NAME={cp}",
                "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml",
                "COMPOSE_PATH_SEPARATOR=:",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(dep / ".env", 0o600)
    (dep / "volumes").mkdir()
    return meta


def _failed_restore_journal(home: Path, slug: str, op_id: str = "op-restore-1") -> dict:
    journal = reg.new_operation_journal(
        intent="RESTORING",
        phase="install",
        state=reg.OP_STATE_FAILED,
        operation_id=op_id,
        error="synthetic restore failure",
        extra={"backup_id": "bak-1"},
    )
    reg.write_operation_journal(home, slug, journal)
    return journal


def test_failed_restore_then_ordinary_stop_preserves_journal(home: Path) -> None:
    _seed(home)
    journal = _failed_restore_journal(home, "alpha")
    op_before = journal["operation_id"]

    def fake_run(argv: list[str], **kwargs):
        return ProcessResult(list(argv), 0, "", "")

    with (
        mock.patch.object(auth, "build_project_contract", return_value=mock.Mock()),
        mock.patch.object(auth, "invent_owned_resources", return_value=auth.OwnedInventory()),
        mock.patch.object(auth, "_validate_effective_compose", return_value=None),
        mock.patch.object(auth, "_verify_env_selectors", return_value=None),
        mock.patch("sbfleet.projects.run", side_effect=fake_run),
        mock.patch(
            "sbfleet.health.inspect_containers_result",
            return_value=mock.Mock(ok=True, containers={}, error=None),
        ),
        mock.patch.object(auth.up, "verify_deployment_vendor", return_value=None),
        mock.patch.object(auth.up, "verify_stamp_matches_meta", return_value=None),
        mock.patch.object(auth.up, "cache_dir", return_value=home / "cache" / ("a" * 40)),
    ):
        (home / "cache" / ("a" * 40)).mkdir(parents=True)
        stop_project(home, "alpha")

    after = reg.read_operation_journal(home, "alpha")
    assert after is not None
    assert after.get("intent") == "RESTORING"
    assert after.get("state") == reg.OP_STATE_FAILED
    assert after.get("operation_id") == op_before
    assert after.get("intent") != "STOPPED"
    # Start must still refuse.
    with (
        mock.patch.object(auth, "build_project_contract", return_value=mock.Mock()),
        mock.patch.object(auth, "invent_owned_resources", return_value=auth.OwnedInventory()),
        mock.patch.object(auth, "_validate_effective_compose", return_value=None),
        mock.patch.object(auth.up, "verify_deployment_vendor", return_value=None),
        mock.patch.object(auth.up, "verify_stamp_matches_meta", return_value=None),
        mock.patch.object(auth.up, "cache_dir", return_value=home / "cache" / ("a" * 40)),
    ):
        with pytest.raises(auth.AuthorityError, match="unresolved"):
            with auth.authorize_mutation(home, "alpha", intent="start"):
                pass


def test_failed_update_then_new_maintenance_refused(home: Path) -> None:
    _seed(home)
    journal = reg.new_operation_journal(
        intent="UPDATING",
        phase="promote",
        state=reg.OP_STATE_FAILED,
        operation_id="op-upd-1",
    )
    reg.write_operation_journal(home, "alpha", journal)
    with (
        mock.patch.object(auth, "build_project_contract", return_value=mock.Mock()),
        mock.patch.object(auth, "invent_owned_resources", return_value=auth.OwnedInventory()),
        mock.patch.object(auth, "_validate_effective_compose", return_value=None),
        mock.patch.object(auth.up, "verify_deployment_vendor", return_value=None),
        mock.patch.object(auth.up, "verify_stamp_matches_meta", return_value=None),
        mock.patch.object(auth.up, "cache_dir", return_value=home / "cache" / ("a" * 40)),
    ):
        (home / "cache" / ("a" * 40)).mkdir(parents=True)
        with pytest.raises(auth.AuthorityError, match="blocks a new backup"):
            with auth.authorize_mutation(home, "alpha", intent="backup"):
                pass
        with pytest.raises(auth.AuthorityError, match="blocks a new update"):
            with auth.authorize_mutation(home, "alpha", intent="update"):
                pass


def test_begin_operation_refuses_foreign_unresolved_overwrite(home: Path) -> None:
    meta = _seed(home)
    _failed_restore_journal(home, "alpha", op_id="op-r")
    ctx = auth.MutationContext(
        root=home,
        slug="alpha",
        meta=meta,
        deployment=reg.project_dir(home, "alpha") / "deployment",
        project_dir=reg.project_dir(home, "alpha"),
        compose_project=str(meta["compose_project"]),
        fleet_id=str(meta["fleet_id"]),
        project_id=str(meta["id"]),
        compose_env={},
        operation_id="fresh-op",
        intent="stop",
    )
    with pytest.raises(auth.AuthorityError, match="overwrite unresolved RESTORING"):
        auth.begin_operation(ctx, phase="run")


def test_reviewed_plans_equivalent_detects_drift() -> None:
    a = {
        "ok": True,
        "data": {
            "from": {"ref": "self-hosted/v0.8.2", "sha": "a" * 40},
            "to_ref": "self-hosted/v0.8.2",
            "to_sha": "b" * 40,
            "noop": False,
            "blockers": [],
        },
    }
    b = {
        "ok": True,
        "data": {
            "from": {"ref": "self-hosted/v0.8.2", "sha": "c" * 40},
            "to_ref": "self-hosted/v0.8.2",
            "to_sha": "b" * 40,
            "noop": False,
            "blockers": [],
        },
    }
    assert upd._reviewed_plans_equivalent(a, a) is True
    assert upd._reviewed_plans_equivalent(a, b) is False
