"""Update target surface binding."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from unittest import mock

import pytest
from tests.helpers_upstream import write_cache_marker

from sbfleet import registry as reg
from sbfleet import update as upd
from sbfleet import upstream as up


def _write_target_surface(docker: Path, *, extra: dict[str, str] | None = None) -> None:
    """Minimal approved docker/ surface beyond critical files."""
    docker.mkdir(parents=True, exist_ok=True)
    files = {
        "docker-compose.yml": "services:\n  db:\n    image: supabase/postgres:17\n" + ("x" * 80),
        "run.sh": "#!/bin/sh\necho run-approved\n",
        "setup.sh": "#!/bin/sh\necho setup-approved\n",
        "update.sh": "#!/bin/sh\necho update-approved\n",
        ".env.example": "JWT_SECRET=example\nPOSTGRES_PASSWORD=example\n",
        "upgrades.json": "{}\n",
        "utils/generate-keys.sh": "#!/bin/sh\necho keys\n",
        "utils/add-new-auth-keys.sh": "#!/bin/sh\necho authkeys\n",
        "CHANGELOG.md": "# changelog approved\n",
        "volumes/db/roles.sql": "-- roles approved\n",
    }
    if extra:
        files.update(extra)
    for rel, body in files.items():
        path = docker / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        if rel.endswith(".sh"):
            os.chmod(path, 0o755)


def _materialize_approved(
    root: Path,
    *,
    ref: str = up.PINNED_REF,
    sha: str = up.PINNED_SHA,
    extra: dict[str, str] | None = None,
) -> Path:
    cache = up.cache_dir(root, sha)
    if cache.exists():
        shutil.rmtree(cache)
    cache.mkdir(parents=True)
    docker = cache / "docker"
    _write_target_surface(docker, extra=extra)
    write_cache_marker(cache, sha=sha, ref=ref)
    return cache


def _seed_staging_from_target(staging: Path, target_docker: Path) -> None:
    staging.mkdir(parents=True, mode=0o700)
    for dirpath, _dirnames, filenames in os.walk(target_docker):
        for name in filenames:
            src = Path(dirpath) / name
            rel = src.relative_to(target_docker)
            dest = staging / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
    # Fleet/runtime-owned paths that must not participate in bind equality.
    (staging / ".env").write_text("JWT_SECRET=live-secret-value-long-enough\n", encoding="utf-8")
    (staging / "docker-compose.override.yml").write_text("services: {}\n", encoding="utf-8")
    (staging / ".sbfleet-upstream").write_text(
        f"ref={up.PINNED_REF}\nsha={up.PINNED_SHA}\n", encoding="utf-8"
    )
    (staging / ".supabase-version").write_text(f"ref={up.PINNED_REF}\n", encoding="utf-8")
    (staging / "backups").mkdir(exist_ok=True)
    (staging / "backups" / "pre-update.tgz").write_bytes(b"plaintext-config-tar")
    (staging / ".run-home").mkdir(exist_ok=True)
    (staging / ".run-home" / "marker").write_text("private\n", encoding="utf-8")


def _live_deployment(tmp_path: Path) -> tuple[Path, Path]:
    root = reg.ensure_root(tmp_path / "home")
    dep = root / "projects" / "demo" / "deployment"
    dep.mkdir(parents=True)
    (dep / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (dep / "docker-compose.override.yml").write_text("services: {}\n", encoding="utf-8")
    (dep / ".env").write_text("JWT_SECRET=abcdefghijklmnopqrstuvwxyz012345\n", encoding="utf-8")
    (dep / "run.sh").write_text("#!/bin/sh\necho live\n", encoding="utf-8")
    (dep / ".supabase-version").write_text("ref=self-hosted/v0.8.1\n", encoding="utf-8")
    (dep / ".sbfleet-upstream").write_text(
        "ref=self-hosted/v0.8.1\nsha=8c7a4d9dbbaf8b552893822e89d7bf06f33f9220\n",
        encoding="utf-8",
    )
    return root, dep


def test_bind_accepts_matching_full_surface(tmp_path: Path) -> None:
    root, _dep = _live_deployment(tmp_path)
    cache = _materialize_approved(root)
    staging = root / "staging" / "ok"
    _seed_staging_from_target(staging, cache / "docker")
    got = upd.bind_staging_to_approved_target(
        root,
        staging,
        to_ref=up.PINNED_REF,
        to_sha=up.PINNED_SHA,
        from_ref="self-hosted/v0.8.1",
        from_sha=up.KNOWN_REF_SHAS["self-hosted/v0.8.1"],
    )
    assert got == cache


def test_moved_ref_retargeted_target_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tag still named PINNED_REF but resolved/approved SHA disagrees with staged claim."""
    root, dep = _live_deployment(tmp_path)
    before = upd.hash_authority_surface(dep)
    cache = _materialize_approved(root)
    staging = root / "staging" / "moved"
    _seed_staging_from_target(staging, cache / "docker")
    moved_sha = "ffffffffffffffffffffffffffffffffffffffff"
    monkeypatch.setitem(up.KNOWN_REF_SHAS, up.PINNED_REF, moved_sha)
    with pytest.raises(upd.UpdateError, match="ref↔SHA mismatch|does not match approved SHA"):
        upd.bind_staging_to_approved_target(
            root,
            staging,
            to_ref=up.PINNED_REF,
            to_sha=up.PINNED_SHA,
        )
    assert upd.hash_authority_surface(dep) == before


def test_staged_run_sh_mismatch_refuses(tmp_path: Path) -> None:
    root, dep = _live_deployment(tmp_path)
    before = upd.hash_authority_surface(dep)
    cache = _materialize_approved(root)
    staging = root / "staging" / "bad-run"
    _seed_staging_from_target(staging, cache / "docker")
    (staging / "run.sh").write_text("#!/bin/sh\necho unexpected-run\n", encoding="utf-8")
    with pytest.raises(upd.UpdateError, match="digest mismatch for run.sh"):
        upd.bind_staging_to_approved_target(
            root, staging, to_ref=up.PINNED_REF, to_sha=up.PINNED_SHA
        )
    assert upd.hash_authority_surface(dep) == before


def test_unexpected_compose_bytes_refuse(tmp_path: Path) -> None:
    root, dep = _live_deployment(tmp_path)
    before = upd.hash_authority_surface(dep)
    cache = _materialize_approved(root)
    staging = root / "staging" / "bad-compose"
    _seed_staging_from_target(staging, cache / "docker")
    (staging / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: evil/postgres:latest\n" + ("y" * 80),
        encoding="utf-8",
    )
    with pytest.raises(upd.UpdateError, match="digest mismatch for docker-compose.yml"):
        upd.bind_staging_to_approved_target(
            root, staging, to_ref=up.PINNED_REF, to_sha=up.PINNED_SHA
        )
    assert upd.hash_authority_surface(dep) == before


def test_missing_approved_target_file_refuses(tmp_path: Path) -> None:
    root, dep = _live_deployment(tmp_path)
    before = upd.hash_authority_surface(dep)
    cache = _materialize_approved(root)
    staging = root / "staging" / "missing"
    _seed_staging_from_target(staging, cache / "docker")
    (staging / "CHANGELOG.md").unlink()
    with pytest.raises(upd.UpdateError, match="missing approved target file"):
        upd.bind_staging_to_approved_target(
            root, staging, to_ref=up.PINNED_REF, to_sha=up.PINNED_SHA
        )
    assert upd.hash_authority_surface(dep) == before


def test_extra_unexpected_upstream_owned_file_refuses(tmp_path: Path) -> None:
    root, dep = _live_deployment(tmp_path)
    before = upd.hash_authority_surface(dep)
    cache = _materialize_approved(root)
    staging = root / "staging" / "extra"
    _seed_staging_from_target(staging, cache / "docker")
    (staging / "evil-extra.sh").write_text("#!/bin/sh\necho pwn\n", encoding="utf-8")
    with pytest.raises(upd.UpdateError, match="unexpected staged upstream-owned"):
        upd.bind_staging_to_approved_target(
            root, staging, to_ref=up.PINNED_REF, to_sha=up.PINNED_SHA
        )
    assert upd.hash_authority_surface(dep) == before


def test_wrong_approved_sha_refuses(tmp_path: Path) -> None:
    root, dep = _live_deployment(tmp_path)
    before = upd.hash_authority_surface(dep)
    cache = _materialize_approved(root)
    staging = root / "staging" / "wrong-sha"
    _seed_staging_from_target(staging, cache / "docker")
    wrong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with pytest.raises(upd.UpdateError, match="ref↔SHA mismatch|does not match approved SHA"):
        upd.bind_staging_to_approved_target(root, staging, to_ref=up.PINNED_REF, to_sha=wrong)
    assert upd.hash_authority_surface(dep) == before


def test_critical_only_match_with_divergent_noncritical_refuses(tmp_path: Path) -> None:
    """critical digests matching is insufficient when non-critical updater-owned drifts."""
    root, dep = _live_deployment(tmp_path)
    before = upd.hash_authority_surface(dep)
    cache = _materialize_approved(root)
    staging = root / "staging" / "critical-only"
    _seed_staging_from_target(staging, cache / "docker")
    (staging / "CHANGELOG.md").write_text("# changelog DIVERGED\n", encoding="utf-8")
    (staging / "volumes" / "db" / "roles.sql").write_text("-- roles DIVERGED\n", encoding="utf-8")
    marker = json.loads((cache / ".sbfleet-cache.json").read_text(encoding="utf-8"))
    critical = up.validate_critical_digests_manifest(marker, expected_sha=up.PINNED_SHA)
    for rel, digest in critical.items():
        assert upd._sha256_file(staging / rel) == digest
    with pytest.raises(upd.UpdateError, match="digest mismatch"):
        upd.bind_staging_to_approved_target(
            root, staging, to_ref=up.PINNED_REF, to_sha=up.PINNED_SHA
        )
    assert upd.hash_authority_surface(dep) == before


def test_fleet_runtime_owned_paths_not_compared(tmp_path: Path) -> None:
    root, _dep = _live_deployment(tmp_path)
    cache = _materialize_approved(root)
    staging = root / "staging" / "fleet"
    _seed_staging_from_target(staging, cache / "docker")
    (staging / ".env").write_text(
        "JWT_SECRET=completely-different-secret-value\n",
        encoding="utf-8",
    )
    (staging / "docker-compose.override.yml").write_text(
        "services:\n  x: {}\n",
        encoding="utf-8",
    )
    (staging / ".sbfleet-upstream").write_text(
        "ref=other\nsha=deadbeef\n",
        encoding="utf-8",
    )
    (staging / "backups" / "other.tgz").write_bytes(b"more")
    upd.bind_staging_to_approved_target(root, staging, to_ref=up.PINNED_REF, to_sha=up.PINNED_SHA)


def test_inspect_enforces_to_sha(tmp_path: Path) -> None:
    staging = tmp_path / "stage"
    staging.mkdir()
    (staging / ".supabase-version").write_text(f"ref={up.PINNED_REF}\n", encoding="utf-8")
    result = mock.Mock(returncode=0, stdout="Update applied cleanly.\n", stderr="", timed_out=False)
    with pytest.raises(upd.UpdateError, match="does not match approved SHA"):
        upd.inspect_updater_result(
            staging,
            result,
            to_ref=up.PINNED_REF,
            to_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )


def test_source_ref_sha_mismatch_refuses(tmp_path: Path) -> None:
    root, dep = _live_deployment(tmp_path)
    before = upd.hash_authority_surface(dep)
    cache = _materialize_approved(root)
    staging = root / "staging" / "src-sha"
    _seed_staging_from_target(staging, cache / "docker")
    with pytest.raises(upd.UpdateError, match="source ref↔SHA mismatch"):
        upd.bind_staging_to_approved_target(
            root,
            staging,
            to_ref=up.PINNED_REF,
            to_sha=up.PINNED_SHA,
            from_ref="self-hosted/v0.8.1",
            from_sha="cccccccccccccccccccccccccccccccccccccccc",
        )
    assert upd.hash_authority_surface(dep) == before


def test_no_custom_merge_engine_reintroduced() -> None:
    for name in (
        "_promote_vendor",
        "_should_preserve",
        "_append_missing_env_keys",
        "_PRESERVE_PREFIXES",
    ):
        assert not hasattr(upd, name)
    assert hasattr(upd, "bind_staging_to_approved_target")
    assert hasattr(upd, "is_fleet_or_runtime_owned")
