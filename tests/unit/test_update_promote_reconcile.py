"""Update promote reconcile."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet import update as upd
from sbfleet.cli import EXIT_SAFETY


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed_paths(tmp: Path) -> tuple[Path, Path, Path]:
    staging = tmp / "staging" / f"update-{uuid.uuid4().hex}"
    live = tmp / "live"
    quarantine = tmp / "staging" / f"update-quarantine-{uuid.uuid4().hex}"
    staging.mkdir(parents=True)
    live.mkdir(parents=True)
    (staging / "a.yml").write_text("target-a\n", encoding="utf-8")
    (staging / "b.yml").write_text("target-b\n", encoding="utf-8")
    (live / "a.yml").write_text("source-a\n", encoding="utf-8")
    (live / "b.yml").write_text("source-b\n", encoding="utf-8")
    return staging, live, quarantine


def test_promote_record_written_before_mutation_and_excludes_self(tmp_path: Path) -> None:
    staging, live, quarantine = _seed_paths(tmp_path)
    rels = upd.list_promote_relpaths(staging)
    assert upd.PROMOTE_RECORD_NAME not in rels
    record = upd.build_promote_record(
        operation_id="op1",
        from_ref="self-hosted/v0.8.1",
        from_sha="1" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="2" * 40,
        backup_id="bk1",
        staging=staging,
        deployment=live,
        quarantine=quarantine,
        relpaths=rels,
    )
    path = upd.write_promote_record(staging, record)
    assert path == upd.promote_record_path(staging)
    assert path.is_file()
    # Still excluded from promote inventory after write.
    assert upd.PROMOTE_RECORD_NAME not in upd.list_promote_relpaths(staging)
    for entry in record["paths"]:
        assert entry["progress"] == upd.PROGRESS_INTENDED
        assert entry["pre"]["kind"] == upd.KIND_REGULAR_FILE
        assert entry["target"]["kind"] == upd.KIND_REGULAR_FILE
        assert entry["pre"]["sha256"] != entry["target"]["sha256"]


def test_journal_summary_lag_does_not_invent_mutation(tmp_path: Path) -> None:
    staging, live, quarantine = _seed_paths(tmp_path)
    rels = upd.list_promote_relpaths(staging)
    record = upd.build_promote_record(
        operation_id="op-lag",
        from_ref="self-hosted/v0.8.1",
        from_sha="1" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="2" * 40,
        backup_id="bk1",
        staging=staging,
        deployment=live,
        quarantine=quarantine,
        relpaths=rels,
    )
    upd.write_promote_record(staging, record)
    # Simulate journal falsely claiming completion while live still source.
    false_journal = {"evidence": {"promote_verified_count": 99, "paths_promoted_complete": True}}
    diagnoses = upd.diagnose_promote_paths(live, record)
    assert all(d["classification"] == upd.CLASS_EXACT_SOURCE for d in diagnoses)
    assert upd.promotion_phase_label(record, diagnoses) == "no_promotion_began"
    # Journal claim must not flip classification.
    assert false_journal["evidence"]["paths_promoted_complete"] is True


def test_operation_scoped_records_do_not_overwrite(tmp_path: Path) -> None:
    live = tmp_path / "live"
    live.mkdir()
    (live / "f.yml").write_text("src\n", encoding="utf-8")
    staging_a = tmp_path / "staging" / "update-aaa"
    staging_b = tmp_path / "staging" / "update-bbb"
    for staging, op in ((staging_a, "aaa"), (staging_b, "bbb")):
        staging.mkdir(parents=True)
        (staging / "f.yml").write_text(f"tgt-{op}\n", encoding="utf-8")
        rec = upd.build_promote_record(
            operation_id=op,
            from_ref="self-hosted/v0.8.1",
            from_sha="1" * 40,
            to_ref="self-hosted/v0.8.2",
            to_sha="2" * 40,
            backup_id=f"bk-{op}",
            staging=staging,
            deployment=live,
            quarantine=tmp_path / f"q-{op}",
            relpaths=["f.yml"],
        )
        upd.write_promote_record(staging, rec)
    a = upd.load_promote_record(upd.promote_record_path(staging_a))
    b = upd.load_promote_record(upd.promote_record_path(staging_b))
    assert a["operation_id"] == "aaa"
    assert b["operation_id"] == "bbb"
    assert a["backup_id"] != b["backup_id"]
    assert a["paths"][0]["target"]["sha256"] != b["paths"][0]["target"]["sha256"]


def test_symlink_live_classifies_foreign(tmp_path: Path) -> None:
    staging = tmp_path / "staging" / "update-sym"
    live = tmp_path / "live"
    staging.mkdir(parents=True)
    live.mkdir()
    (staging / "a.yml").write_text("target-a\n", encoding="utf-8")
    (live / "a.yml").write_text("source-a\n", encoding="utf-8")
    record = upd.build_promote_record(
        operation_id="op-sym",
        from_ref="self-hosted/v0.8.1",
        from_sha="1" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="2" * 40,
        backup_id="bk1",
        staging=staging,
        deployment=live,
        quarantine=tmp_path / "q",
        relpaths=["a.yml"],
    )
    (live / "a.yml").unlink()
    (live / "a.yml").symlink_to("/tmp/elsewhere")
    diagnoses = upd.diagnose_promote_paths(live, record)
    assert diagnoses[0]["classification"] == upd.CLASS_FOREIGN
    assert upd.promotion_phase_label(record, diagnoses) == "foreign_or_unexpected"


def test_addition_absent_pre_is_exact_source_when_still_absent(tmp_path: Path) -> None:
    staging = tmp_path / "staging" / "update-add"
    live = tmp_path / "live"
    staging.mkdir(parents=True)
    live.mkdir()
    (staging / "new.yml").write_text("new\n", encoding="utf-8")
    record = upd.build_promote_record(
        operation_id="op-add",
        from_ref="self-hosted/v0.8.1",
        from_sha="1" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="2" * 40,
        backup_id="bk1",
        staging=staging,
        deployment=live,
        quarantine=tmp_path / "q",
        relpaths=["new.yml"],
    )
    assert record["paths"][0]["pre"]["kind"] == upd.KIND_ABSENT
    diagnoses = upd.diagnose_promote_paths(live, record)
    assert diagnoses[0]["classification"] == upd.CLASS_EXACT_SOURCE


def test_mechanical_promote_verifies_before_progress(tmp_path: Path) -> None:
    staging, live, quarantine = _seed_paths(tmp_path)
    rels = upd.list_promote_relpaths(staging)
    record = upd.build_promote_record(
        operation_id="op-p",
        from_ref="self-hosted/v0.8.1",
        from_sha="1" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="2" * 40,
        backup_id="bk1",
        staging=staging,
        deployment=live,
        quarantine=quarantine,
        relpaths=rels,
    )
    upd.write_promote_record(staging, record)
    seen: list[tuple[str, str]] = []

    def hook(rel: str, phase: str) -> None:
        seen.append((rel, phase))
        if phase == "after_first":
            # After first verified path, record must show verified for that path.
            reloaded = upd.load_promote_record(upd.promote_record_path(staging))
            first = reloaded["paths"][0]
            assert first["progress"] == upd.PROGRESS_VERIFIED
            assert (live / first["rel"]).read_text(encoding="utf-8").startswith("target-")

    upd.mechanical_promote(staging, live, record=record, quarantine=quarantine, crash_hook=hook)
    assert ("__record__", "after_record") in seen
    assert ("__all__", "after_all_files") in seen
    reloaded = upd.load_promote_record(upd.promote_record_path(staging))
    assert reloaded["paths_promoted_complete"] is True
    assert all(p["progress"] == upd.PROGRESS_VERIFIED for p in reloaded["paths"])


def test_reconcile_refuses_without_operation_id(tmp_path: Path) -> None:
    code = upd.update_project(
        tmp_path,
        "x",
        to_ref=None,
        dry_run=False,
        yes=True,
        reconcile=True,
        operation_id=None,
    )
    assert code == EXIT_SAFETY


def test_reconcile_refuses_combined_with_to(tmp_path: Path) -> None:
    code = upd.update_project(
        tmp_path,
        "x",
        to_ref="self-hosted/v0.8.2",
        dry_run=False,
        yes=True,
        reconcile=True,
        operation_id="abc",
    )
    assert code == EXIT_SAFETY


def test_reconcile_diagnose_only_when_record_missing(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    slug = "rec"
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
            "gateway": 23010,
            "db_direct": 23011,
            "pooler_session": 23012,
            "pooler_transaction": 23013,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:23010",
        "upstream": {"ref": "self-hosted/v0.8.1", "sha": "a" * 40},
        "creation_complete": True,
        "image_digests": {},
    }
    reg.write_project(home, meta)
    dep = reg.project_dir(home, slug) / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    op_id = uuid.uuid4().hex
    reg.write_operation_journal(
        home,
        slug,
        reg.new_operation_journal(
            intent="UPDATING",
            phase="promoting",
            state=reg.OP_STATE_IN_PROGRESS,
            operation_id=op_id,
            extra={"evidence": {"backup_id": "bk-x"}},
        ),
    )

    class FakeCtx:
        def __init__(self) -> None:
            self.root = home
            self.slug = slug
            self.operation_id = "wrong"
            self.deployment = dep
            self.meta = meta
            self.intent = "update"
            self.contract = None
            self.compose_project = meta["compose_project"]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        "sbfleet.authority.authorize_mutation",
        lambda *a, **k: FakeCtx(),
    )
    monkeypatch.setattr(
        "sbfleet.authority.record_operation_phase",
        lambda *a, **k: {},
    )
    code = upd.reconcile_interrupted_update(home, slug, operation_id=op_id, yes=True)
    assert code == EXIT_SAFETY


def test_classify_partial_promotion_phase(tmp_path: Path) -> None:
    staging, live, quarantine = _seed_paths(tmp_path)
    record = upd.build_promote_record(
        operation_id="op-part",
        from_ref="self-hosted/v0.8.1",
        from_sha="1" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="2" * 40,
        backup_id="bk1",
        staging=staging,
        deployment=live,
        quarantine=quarantine,
        relpaths=["a.yml", "b.yml"],
    )
    # Promote only a.yml manually.
    (live / "a.yml").write_text("target-a\n", encoding="utf-8")
    diagnoses = upd.diagnose_promote_paths(live, record)
    assert upd.promotion_phase_label(record, diagnoses) == "partially_promoted"
    classes = {d["rel"]: d["classification"] for d in diagnoses}
    assert classes["a.yml"] == upd.CLASS_EXACT_TARGET
    assert classes["b.yml"] == upd.CLASS_EXACT_SOURCE
