"""Restore live preflight matrix.

Creates one owned disposable project, recovery-verifies a backup, then proves
pre-mutation refusals do not leave blocking RESTORING journals and that
subsequent backup / update --dry-run / remove remain available.
"""

from __future__ import annotations

import json
import os
import shutil
import tarfile
import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet.backup import create_backup, restore_backup, set_fleet_recipients
from sbfleet.cli import EXIT_BACKUP, EXIT_FAILURE, EXIT_OK
from sbfleet.health import HEALTHY, collect_status, lifecycle_op_succeeded
from sbfleet.process import run
from sbfleet.projects import create_project, stop_project
from sbfleet.projects_remove import remove_project
from sbfleet.update import update_project

pytestmark = pytest.mark.docker


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    r = run(
        ["docker", "info"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=30.0,
        check=False,
    )
    return r.ok


def _age_ok() -> bool:
    return shutil.which("age") is not None and shutil.which("age-keygen") is not None


def _run(argv: list[str], *, cwd: Path | None = None, timeout: float = 120.0):
    return run(
        argv,
        cwd=cwd,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=timeout,
        check=False,
    )


@pytest.fixture()
def disposable_home(tmp_path: Path):
    if not _docker_ok():
        pytest.skip("docker unavailable")
    if not _age_ok():
        pytest.skip("age/age-keygen unavailable")
    run_id = uuid.uuid4().hex[:12]
    root = reg.ensure_root(tmp_path / f"sbfleet-test-{run_id}")
    id_path = root / "age-identity.txt"
    gen = _run(["age-keygen", "-o", str(id_path)])
    assert gen.ok, gen.stderr
    os.chmod(id_path, 0o600)
    pub = ""
    for line in id_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# public key:"):
            pub = line.split(":", 1)[1].strip()
            break
    assert pub.startswith("age1")
    set_fleet_recipients(root, [pub])
    fleet = reg.fleet_id(root)
    yield {"root": root, "identity": id_path, "run_id": run_id, "fleet_id": fleet}
    import fixture_cleanup

    fixture_cleanup.cleanup_labeled_fleet_resources(fleet_id=fleet)


def _assert_not_wedged(root: Path, slug: str) -> None:
    journal = reg.read_operation_journal(root, slug)
    assert journal is None or not reg.journal_blocks_ordinary_start(journal), journal


def _forge_wrong_project_archive(
    *, archive: Path, identity: Path, out: Path, wrong_pid: str
) -> None:
    staging = out.parent / f"forge-{uuid.uuid4().hex[:8]}"
    staging.mkdir(parents=True, mode=0o700)
    plain = staging / "backup.tar"
    dec = _run(
        ["age", "-d", "-i", str(identity), "-o", str(plain), str(archive)],
        timeout=120.0,
    )
    assert dec.ok, (dec.stderr or "")[:200]
    extract = staging / "extract"
    extract.mkdir()
    with tarfile.open(plain, "r:") as tf:
        tf.extractall(extract)
    man_path = extract / "manifest.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    man["project_id"] = wrong_pid
    man_path.write_text(json.dumps(man), encoding="utf-8")
    forged_tar = staging / "forged.tar"
    with tarfile.open(forged_tar, "w:") as tf:
        for path in extract.rglob("*"):
            if path.is_file():
                tf.add(path, arcname=str(path.relative_to(extract)))
    pub = next(
        line.split(":", 1)[1].strip()
        for line in identity.read_text(encoding="utf-8").splitlines()
        if line.startswith("# public key:")
    )
    enc = _run(
        ["age", "-r", pub, "-o", str(out), str(forged_tar)],
        timeout=120.0,
    )
    assert enc.ok, (enc.stderr or "")[:200]
    shutil.rmtree(staging, ignore_errors=True)


def test_restore_preflight_refusals_do_not_wedge_then_ops_succeed(
    disposable_home: dict,
) -> None:
    root: Path = disposable_home["root"]
    id_path: Path = disposable_home["identity"]
    slug = f"qa{disposable_home['run_id'][:8]}"

    create_project(root, slug, display_name="QA Bug002", start=True)
    report = collect_status(root, slug)
    assert lifecycle_op_succeeded(report, expect=HEALTHY), report.lifecycle

    code = create_backup(root, slug, verify=True, identity=str(id_path))
    assert code == EXIT_OK
    meta = reg.read_project(root, slug)
    backup_dir = root / "backups" / str(meta["id"])
    archives = sorted(backup_dir.glob("*.tar.age"))
    assert archives, "expected recovery archive"
    archive = archives[-1]
    # Host cannot read container-owned PGDATA; prove target unchanged via HEALTHY + meta.
    meta_before = reg.read_project(root, slug)
    report_before = collect_status(root, slug)
    assert lifecycle_op_succeeded(report_before, expect=HEALTHY), report_before.lifecycle

    def _target_still_healthy() -> None:
        _assert_not_wedged(root, slug)
        assert reg.read_project(root, slug)["id"] == meta_before["id"]
        report = collect_status(root, slug)
        assert lifecycle_op_succeeded(report, expect=HEALTHY), report.lifecycle

    # --- missing archive ---
    code = restore_backup(
        root, slug, str(root / "missing-archive.tar.age"), yes=True, identity=str(id_path)
    )
    assert code == EXIT_FAILURE
    _target_still_healthy()

    # --- corrupt / truncated ---
    corrupt = root / "corrupt.tar.age"
    corrupt.write_bytes(b"not-an-age-ciphertext")
    code = restore_backup(root, slug, str(corrupt), yes=True, identity=str(id_path))
    assert code != 0
    _target_still_healthy()

    # --- wrong age identity ---
    bad_id = root / "wrong-identity.txt"
    gen = _run(["age-keygen", "-o", str(bad_id)])
    assert gen.ok
    os.chmod(bad_id, 0o600)
    code = restore_backup(root, slug, str(archive), yes=True, identity=str(bad_id))
    assert code == EXIT_BACKUP
    _target_still_healthy()

    # --- wrong-project archive (forged project_id) ---
    wrong = root / "wrong-project.tar.age"
    _forge_wrong_project_archive(
        archive=archive,
        identity=id_path,
        out=wrong,
        wrong_pid=str(uuid.uuid4()),
    )
    code = restore_backup(root, slug, str(wrong), yes=True, identity=str(id_path))
    assert code == EXIT_BACKUP
    _target_still_healthy()

    # Subsequent ops must not be blocked by the refusals above.
    code = create_backup(root, slug, verify=True, identity=str(id_path))
    assert code == EXIT_OK

    up_ref = str((meta.get("upstream") or {}).get("ref") or "")
    assert up_ref
    dry = update_project(
        root,
        slug,
        to_ref=up_ref,
        dry_run=True,
        yes=False,
        identity=str(id_path),
    )
    # Same-pin dry-run may exit 5 (last_verified-mismatch) but must not be journal-blocked.
    assert dry in {EXIT_OK, 5}, dry
    _assert_not_wedged(root, slug)

    stop_project(root, slug)
    rem = remove_project(root, slug, yes=True, no_backup=False)
    assert rem == EXIT_OK
