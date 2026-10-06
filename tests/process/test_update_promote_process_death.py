"""Update promote process death."""

from __future__ import annotations

import os
import signal
import time
import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet import update as upd
from sbfleet.health import FAILED, collect_status, status_exit_code
from sbfleet.process import ProcessResult


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed_project(home: Path, slug: str = "crashu") -> dict:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": 24010,
            "db_direct": 24011,
            "pooler_session": 24012,
            "pooler_transaction": 24013,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:24010",
        "upstream": {"ref": "self-hosted/v0.8.1", "sha": "a" * 40},
        "creation_complete": True,
        "image_digests": {},
    }
    reg.write_project(home, meta)
    (reg.project_dir(home, slug) / "deployment").mkdir(parents=True)
    return meta


def _prepare_promote_tree(home: Path, slug: str, op_id: str) -> tuple[Path, Path, Path, dict]:
    staging = home / "staging" / f"update-{op_id}"
    quarantine = home / "staging" / f"update-quarantine-{op_id}"
    live = reg.project_dir(home, slug) / "deployment"
    staging.mkdir(parents=True, mode=0o700)
    live.mkdir(parents=True, exist_ok=True)
    for name, src, tgt in (
        ("one.txt", "src-one\n", "tgt-one\n"),
        ("two.txt", "src-two\n", "tgt-two\n"),
        ("three.txt", "src-three\n", "tgt-three\n"),
    ):
        (live / name).write_text(src, encoding="utf-8")
        (staging / name).write_text(tgt, encoding="utf-8")
    record = upd.build_promote_record(
        operation_id=op_id,
        from_ref="self-hosted/v0.8.1",
        from_sha="a" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="b" * 40,
        backup_id="bk-crash",
        staging=staging,
        deployment=live,
        quarantine=quarantine,
        relpaths=["one.txt", "three.txt", "two.txt"],
    )
    upd.write_promote_record(staging, record)
    reg.write_operation_journal(
        home,
        slug,
        reg.new_operation_journal(
            intent="UPDATING",
            phase="promoting",
            state=reg.OP_STATE_IN_PROGRESS,
            operation_id=op_id,
            extra={
                "evidence": {
                    "promote_record_path": str(upd.promote_record_path(staging)),
                    "backup_id": "bk-crash",
                    "promote_count": 3,
                    # Intentionally lagging / false-ready summary:
                    "promote_verified_count": 0,
                }
            },
        ),
    )
    return staging, live, quarantine, record


@pytest.mark.parametrize(
    "kill_phase",
    [
        "after_record",
        "after_first",
        "mid_after_2",
        "after_all_files",
    ],
)
def test_sigkill_during_promote_preserves_canonical_record(
    home: Path, kill_phase: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    slug = "crashu"
    _seed_project(home, slug)
    op_id = uuid.uuid4().hex
    staging, live, quarantine, _record = _prepare_promote_tree(home, slug, op_id)
    ready = home / f"ready-{kill_phase}.txt"

    def child() -> None:
        rec = upd.load_promote_record(upd.promote_record_path(staging))

        def hook(rel: str, phase: str) -> None:
            if phase == kill_phase:
                ready.write_text(f"{op_id}:{phase}:{rel}", encoding="utf-8")
                time.sleep(0.05)
                os.kill(os.getpid(), signal.SIGKILL)

        upd.mechanical_promote(
            staging,
            live,
            record=rec,
            quarantine=quarantine,
            crash_hook=hook,
        )
        # If kill phase is after_all_files, hook fires then process dies before return.
        ready.write_text(f"{op_id}:unexpected-complete", encoding="utf-8")

    pid = os.fork()
    if pid == 0:
        try:
            child()
        finally:
            os._exit(1)
    deadline = time.time() + 8.0
    while time.time() < deadline and not ready.exists():
        time.sleep(0.02)
    assert ready.exists(), f"child did not reach kill phase {kill_phase}"
    _pid, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL

    journal = reg.read_operation_journal(home, slug) or {}
    assert journal.get("operation_id") == op_id
    assert journal.get("intent") == "UPDATING"
    assert reg.journal_is_unresolved(journal)

    rec = upd.load_promote_record(upd.promote_record_path(staging))
    assert rec["operation_id"] == op_id
    assert rec["to_sha"] == "b" * 40
    assert rec["backup_id"] == "bk-crash"
    diagnoses = upd.diagnose_promote_paths(live, rec)
    verified = [d for d in diagnoses if d["classification"] == upd.CLASS_EXACT_TARGET]
    source = [d for d in diagnoses if d["classification"] == upd.CLASS_EXACT_SOURCE]
    # Canonical record progress must not exceed established live mutations.
    for entry in rec["paths"]:
        live_state = upd.observe_path_state(live / entry["rel"])
        if entry["progress"] == upd.PROGRESS_VERIFIED:
            assert upd.path_states_equal(live_state, entry["target"])
    if kill_phase == "after_record":
        assert not verified
        assert len(source) == 3
        assert rec.get("promotion_begun") is True
        assert rec.get("paths_promoted_complete") is not True
    elif kill_phase == "after_first":
        assert len(verified) == 1
        assert len(source) == 2
    elif kill_phase == "mid_after_2":
        assert len(verified) == 2
        assert len(source) == 1
    elif kill_phase == "after_all_files":
        assert len(verified) == 3
        assert rec.get("paths_promoted_complete") is True

    monkeypatch.setattr(
        "sbfleet.health.run",
        lambda *a, **k: ProcessResult(["docker"], 0, "", ""),
    )
    report = collect_status(home, slug)
    assert report.lifecycle == FAILED
    assert status_exit_code(report) == 1

    # Ordinary new update refuses unresolved journal (no bypass).
    from sbfleet.authority import AuthorityError, authorize_mutation

    with pytest.raises(AuthorityError, match="unresolved"):
        with authorize_mutation(
            home,
            slug,
            intent="update",
            validate_compose=False,
            invent_live=False,
            skip_pin_vendor_check=True,
        ):
            pass

    # Foreign mutation refuses classification as source/target.
    foreign_path = live / diagnoses[0]["rel"]
    if foreign_path.is_file() and not foreign_path.is_symlink():
        foreign_path.write_text("FOREIGN-BYTES\n", encoding="utf-8")
        diagnoses2 = upd.diagnose_promote_paths(live, rec)
        assert any(d["classification"] == upd.CLASS_FOREIGN for d in diagnoses2)


def test_sigkill_after_runtime_flag_before_journal_complete(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Promotion complete + runtime_verified durable; journal still in_progress."""
    slug = "crashu"
    _seed_project(home, slug)
    op_id = uuid.uuid4().hex
    staging, live, quarantine, record = _prepare_promote_tree(home, slug, op_id)
    ready = home / "ready-runtime.txt"

    def child() -> None:
        rec = upd.load_promote_record(upd.promote_record_path(staging))
        upd.mechanical_promote(staging, live, record=rec, quarantine=quarantine)
        upd.set_promote_record_flags(staging, rec, metadata_advanced=True, runtime_verified=True)
        # Journal intentionally not completed (simulate death before complete_operation).
        ready.write_text(op_id, encoding="utf-8")
        time.sleep(0.05)
        os.kill(os.getpid(), signal.SIGKILL)

    pid = os.fork()
    if pid == 0:
        try:
            child()
        finally:
            os._exit(1)
    deadline = time.time() + 8.0
    while time.time() < deadline and not ready.exists():
        time.sleep(0.02)
    assert ready.exists()
    _pid, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL

    journal = reg.read_operation_journal(home, slug) or {}
    assert journal.get("operation_id") == op_id
    assert journal.get("state") == reg.OP_STATE_IN_PROGRESS
    rec = upd.load_promote_record(upd.promote_record_path(staging))
    assert rec.get("runtime_verified") is True
    assert rec.get("paths_promoted_complete") is True
    diagnoses = upd.diagnose_promote_paths(live, rec)
    assert upd.promotion_phase_label(rec, diagnoses) == "runtime_verified_journal_incomplete"

    monkeypatch.setattr(
        "sbfleet.health.run",
        lambda *a, **k: ProcessResult(["docker"], 0, "", ""),
    )
    assert collect_status(home, slug).lifecycle == FAILED
