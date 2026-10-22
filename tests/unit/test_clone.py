"""Clone preflight must refuse before target creation or source backup."""

import json
import uuid
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from sbfleet import clone
from sbfleet import registry as reg
from sbfleet.cli import build_parser, main
from sbfleet.pooler_rebind import SUPPORTED_PIN


@pytest.fixture
def source(tmp_path):
    root = reg.ensure_root(tmp_path / "fleet")
    pid, fid = str(uuid.uuid4()), reg.fleet_id(root)
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": "source",
        "display_name": "Source",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": 23000,
            "db_direct": 23001,
            "pooler_session": 23002,
            "pooler_transaction": 23003,
        },
        "upstream": dict(SUPPORTED_PIN),
    }
    reg.write_project(root, meta)
    dep = reg.project_dir(root, "source") / "deployment"
    dep.mkdir()
    (dep / ".env").write_text("POSTGRES_PASSWORD=private-secret\n")
    (dep / ".env").chmod(0o600)
    return root, meta, dep


@pytest.mark.parametrize("case", ["target", "target_symlink", "missing", "pin", "identity"])
def test_refuse_before_backup_or_create(source, monkeypatch, case):
    root, meta, dep = source
    if case == "target":
        reg.project_dir(root, "target").mkdir()
    elif case == "target_symlink":
        reg.project_dir(root, "target").symlink_to(root / "absent")
    elif case == "pin":
        meta["upstream"]["sha"] = "0" * 40
        reg.write_project(root, meta)
    elif case == "identity":
        meta["compose_project"] = "foreign"
        reg.write_project(root, meta)

    def forbidden(*args, **kwargs):
        pytest.fail("unsafe clone reached source backup or destination creation")

    monkeypatch.setattr(clone.bak, "_create_backup_locked", forbidden)
    monkeypatch.setattr(clone, "create_project", forbidden)
    result = clone.clone_project(root, "missing" if case == "missing" else "source", "target")
    assert not result["success"]
    assert "private-secret" not in json.dumps(result)
    assert (dep / ".env").read_text() == "POSTGRES_PASSWORD=private-secret\n"


@pytest.mark.parametrize("case", ["authority", "disk", "backup"])
def test_failed_source_preflight_never_creates_target(source, monkeypatch, case):
    root, meta, dep = source
    monkeypatch.setattr(clone.bak, "_require_age", lambda: "/age")
    monkeypatch.setattr(clone.bak, "_resolve_identity", lambda _: root / "identity")
    monkeypatch.setattr(clone.bak, "_fleet_recipients", lambda _: ["recipient"])

    @contextmanager
    def authorized(*args, **kwargs):
        if case == "authority":
            raise clone.auth.AuthorityError("private-secret")
        yield SimpleNamespace(meta=meta, deployment=dep, project_id=meta["id"])

    monkeypatch.setattr(clone.auth, "authorize_mutation", authorized)
    monkeypatch.setattr(clone.auth, "begin_operation", lambda *a, **k: None)
    monkeypatch.setattr(clone.auth, "fail_operation", lambda *a, **k: None)

    def disk(*args, **kwargs):
        if case == "disk":
            raise clone.bak.BackupError("insufficient disk private-secret")

    monkeypatch.setattr(clone.bak, "disk_preflight", disk)
    monkeypatch.setattr(
        clone.bak,
        "_create_backup_locked",
        lambda *a, **k: SimpleNamespace(verification="none", cleanup_ok=True, restart_ok=True),
    )
    monkeypatch.setattr(clone.bak, "_wipe_staging", lambda path: path.rmdir())

    def forbidden(*args, **kwargs):
        pytest.fail("failed source preflight reached target creation")

    monkeypatch.setattr(clone, "create_project", forbidden)
    result = clone.clone_project(root, "source", "target")
    assert not result["success"] and not reg.project_dir(root, "target").exists()
    assert "private-secret" not in json.dumps(result)


def test_new_identity_refuses_collision(source):
    root, meta, _ = source
    target = {**meta, "slug": "target"}
    with pytest.raises(clone.CloneError, match="collision"):
        clone._prove_new_identity(root, meta, target)


def test_cli_json_failure_and_help(tmp_path, capsys):
    assert main(["--home", str(tmp_path / "missing"), "clone", "source", "target", "--json"]) == 5
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == "sbfleet.clone.v1" and not result["success"]
    assert not (tmp_path / "missing").exists()
    assert "clone" in build_parser().format_help()
    assert main(["clone", "source"]) == 2


def test_staging_collision_never_wipes_existing_tree(source, monkeypatch):
    root, _, _ = source
    operation = uuid.UUID("33333333-3333-4333-8333-333333333333")
    staging = root / "staging" / f"clone-{operation.hex}"
    staging.mkdir()
    sentinel = staging / "sentinel"
    sentinel.write_text("preserve")
    monkeypatch.setattr(clone.uuid, "uuid4", lambda: operation)
    monkeypatch.setattr(clone.bak, "_require_age", lambda: "/age")
    monkeypatch.setattr(clone.bak, "_resolve_identity", lambda _: root / "identity")
    monkeypatch.setattr(clone.bak, "_fleet_recipients", lambda _: ["recipient"])
    result = clone.clone_project(root, "source", "target")
    assert not result["success"]
    assert sentinel.read_text() == "preserve"


@pytest.mark.parametrize("changed", ["identity", "operation"])
def test_cleanup_requires_exact_created_target_and_operation(source, monkeypatch, changed):
    root, meta, _ = source

    @contextmanager
    def authorized(*a, **k):
        yield SimpleNamespace(project_id="changed" if changed == "identity" else meta["id"])

    monkeypatch.setattr(clone.auth, "authorize_mutation", authorized)
    monkeypatch.setattr(
        reg,
        "read_operation_journal",
        lambda *a: {"operation_id": "changed" if changed == "operation" else "owned"},
    )

    def forbidden(*a, **k):
        pytest.fail("cleanup attempted lifecycle mutation with changed authority")

    monkeypatch.setattr(clone, "stop_project", forbidden)
    with pytest.raises(clone.CloneError, match="authority_changed"):
        clone._cleanup_target(root, meta, "owned")
