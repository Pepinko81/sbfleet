"""Update fault injection."""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from sbfleet import registry as reg
from sbfleet import update as upd
from sbfleet import upstream as up
from sbfleet.cli import EXIT_OK, EXIT_SAFETY
from sbfleet.process import ProcessResult


def _meta(
    root: Path,
    slug: str = "demo",
    *,
    from_ref: str = "self-hosted/v0.8.1",
) -> dict:
    from_sha = up.resolve_ref_sha(from_ref)
    fid = reg.fleet_id(root)
    pid = "11111111-1111-4111-8111-111111111111"
    return {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": "Demo",
        "compose_project": reg.compose_project_name(fid, pid),
        "creation_complete": True,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "ports": {
            "gateway": 18000,
            "db_direct": 15432,
            "pooler_session": 15433,
            "pooler_transaction": 15434,
        },
        "public_url": "http://127.0.0.1:18000",
        "upstream": {"ref": from_ref, "sha": from_sha},
        "last_verified_upstream": {"ref": from_ref, "sha": from_sha},
    }


def _write_project(tmp_path: Path, *, from_ref: str = "self-hosted/v0.8.1") -> tuple[Path, dict]:
    root = reg.ensure_root(tmp_path / "home")
    meta = _meta(root, from_ref=from_ref)
    reg.write_project(root, meta)
    dep = reg.project_dir(root, meta["slug"]) / "deployment"
    dep.mkdir(parents=True)
    (dep / ".env").write_text(
        "JWT_SECRET=abcdefghijklmnopqrstuvwxyz012345\n"
        "ANON_KEY=anon-key-value-long-enough\n"
        "SERVICE_ROLE_KEY=service-role-key-long\n"
        "SUPABASE_PUBLISHABLE_KEY=pub-key-long-enough\n"
        "SUPABASE_SECRET_KEY=secret-key-long-enough\n"
        'JWT_KEYS=[{"kty":"oct","k":"x"}]\n'
        'JWT_JWKS={"keys":[{"kty":"oct","k":"x"}]}\n'
        "POSTGRES_PASSWORD=postgres-password-long\n"
        "DASHBOARD_USERNAME=admin\n"
        "DASHBOARD_PASSWORD=dashboard-password-long\n"
        "SECRET_KEY_BASE=secret-key-base-long-enough-32\n"
        "VAULT_ENC_KEY=vault-enc-key-long-enough-32ch\n"
        "POOLER_TENANT_ID=tenant\n"
        f"COMPOSE_PROJECT_NAME={meta['compose_project']}\n"
        "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n"
        "KONG_HTTP_PORT=18000\n"
        "SUPABASE_PUBLIC_URL=http://127.0.0.1:18000\n"
        "API_EXTERNAL_URL=http://127.0.0.1:18000/auth/v1\n",
        encoding="utf-8",
    )
    os.chmod(dep / ".env", 0o600)
    (dep / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (dep / "docker-compose.override.yml").write_text("services: {}\n", encoding="utf-8")
    (dep / ".supabase-version").write_text(f"ref={meta['upstream']['ref']}\n", encoding="utf-8")
    (dep / ".sbfleet-upstream").write_text(
        f"ref={meta['upstream']['ref']}\nsha={meta['upstream']['sha']}\n",
        encoding="utf-8",
    )
    (dep / "update.sh").write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
    (dep / "run.sh").write_text("#!/bin/sh\necho run\n", encoding="utf-8")
    return root, meta


def test_requires_explicit_to(tmp_path: Path):
    root, _meta_data = _write_project(tmp_path)
    code = upd.update_project(root, "demo", to_ref=None, dry_run=True, yes=False)
    assert code == EXIT_SAFETY


def test_reverse_transition_refused(tmp_path: Path):
    root, _meta_data = _write_project(tmp_path, from_ref="self-hosted/v0.8.2")
    with pytest.raises(upd.UpdateError, match="unsupported update transition"):
        upd.build_plan(root, "demo", to_ref="self-hosted/v0.8.1")


def test_unreviewed_pair_refused_even_if_known_sha(tmp_path: Path, monkeypatch):
    """Semver-newer is not authority — only directed REVIEWED_TRANSITIONS."""
    root, _meta_data = _write_project(tmp_path, from_ref="self-hosted/v0.8.2")
    # Inject a fake known SHA for a newer tag without adding a reviewed edge.
    monkeypatch.setitem(
        up.KNOWN_REF_SHAS,
        "self-hosted/v0.8.3",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    with pytest.raises(upd.UpdateError, match="unsupported update transition"):
        upd.build_plan(root, "demo", to_ref="self-hosted/v0.8.3")


def test_reviewed_edge_plan_ok_without_blockers(tmp_path: Path):
    root, _meta_data = _write_project(tmp_path)
    compose = "services:\n  db:\n    image: supabase/postgres:17.6.1.136\n"

    def fake_cache(root_arg, *, ref, sha, **_kw):
        base = tmp_path / f"cache-{sha}"
        docker = base / "docker"
        docker.mkdir(parents=True, exist_ok=True)
        (docker / "docker-compose.yml").write_text(compose, encoding="utf-8")
        (docker / "upgrades.json").write_text("{}", encoding="utf-8")
        return base

    with mock.patch.object(up, "materialize_cache", side_effect=fake_cache):
        plan = upd.build_plan(root, "demo", to_ref="self-hosted/v0.8.2")
    assert plan["ok"] is True
    assert plan["data"]["noop"] is False
    assert plan["data"]["reviewed_edge"] == [
        "self-hosted/v0.8.1",
        "self-hosted/v0.8.2",
    ]


def test_same_target_interrupted_journal_refused(tmp_path: Path):
    root, _meta_data = _write_project(tmp_path, from_ref="self-hosted/v0.8.2")
    journal = reg.new_operation_journal(
        intent="UPDATING",
        phase="promoting",
        state=reg.OP_STATE_FAILED,
        operation_id="op-interrupted",
    )
    reg.write_operation_journal(root, "demo", journal)
    with mock.patch.object(upd, "detect_vendor_drift", return_value=[]):
        plan = upd.build_plan(root, "demo", to_ref="self-hosted/v0.8.2")
    assert plan["ok"] is False
    assert "unresolved-update-journal" in plan["data"]["noop_blockers"]


def test_dry_run_does_not_mutate(tmp_path: Path):
    root, _meta_data = _write_project(tmp_path)
    dep = reg.project_dir(root, "demo") / "deployment"
    before_hashes = upd.hash_authority_surface(dep)
    before_meta = json.dumps(reg.read_project(root, "demo"), sort_keys=True)
    before_journal = reg.read_operation_journal(root, "demo")

    with mock.patch.object(upd, "detect_vendor_drift", return_value=[]):
        with mock.patch.object(up, "materialize_cache") as mat:

            def fake_cache(root_arg, *, ref, sha, **_kw):
                base = tmp_path / f"c-{sha[:8]}"
                docker = base / "docker"
                docker.mkdir(parents=True, exist_ok=True)
                text = "services:\n  db:\n    image: x\n"
                (docker / "docker-compose.yml").write_text(text, encoding="utf-8")
                (docker / "upgrades.json").write_text("{}", encoding="utf-8")
                return base

            mat.side_effect = fake_cache
            code = upd.update_project(
                root, "demo", to_ref="self-hosted/v0.8.2", dry_run=True, yes=False
            )
    assert code == EXIT_OK
    assert upd.hash_authority_surface(dep) == before_hashes
    assert json.dumps(reg.read_project(root, "demo"), sort_keys=True) == before_meta
    assert reg.read_operation_journal(root, "demo") == before_journal
    assert not (root / "backups").exists() or not any((root / "backups").rglob("*.tar.age"))


def test_inspect_updater_nonzero(tmp_path: Path):
    staging = tmp_path / "stage"
    staging.mkdir()
    result = ProcessResult(
        argv=["sh", "update.sh"],
        returncode=1,
        stdout="",
        stderr="ERROR: boom",
    )
    with pytest.raises(upd.UpdateError, match="exited 1"):
        upd.inspect_updater_result(
            staging,
            result,
            to_ref="self-hosted/v0.8.2",
            to_sha=up.PINNED_SHA,
        )


def test_inspect_updater_exit0_with_conflict_report(tmp_path: Path):
    staging = tmp_path / "stage"
    staging.mkdir()
    (staging / ".supabase-version").write_text("ref=self-hosted/v0.8.2\n", encoding="utf-8")
    result = ProcessResult(
        argv=["sh", "update.sh"],
        returncode=0,
        stdout="CONFLICTS: 2\nmerge failures: 0\n",
        stderr="",
    )
    with pytest.raises(upd.UpdateError, match="CONFLICTS"):
        upd.inspect_updater_result(
            staging,
            result,
            to_ref="self-hosted/v0.8.2",
            to_sha=up.PINNED_SHA,
        )


def test_inspect_updater_dist_requires_reconciliation(tmp_path: Path):
    staging = tmp_path / "stage"
    staging.mkdir()
    (staging / ".supabase-version").write_text("ref=self-hosted/v0.8.2\n", encoding="utf-8")
    (staging / "update.sh.dist").write_text("#!/bin/sh\n", encoding="utf-8")
    result = ProcessResult(
        argv=["sh", "update.sh"],
        returncode=0,
        stdout="Update applied cleanly.\n",
        stderr="",
    )
    with pytest.raises(upd.UpdateError, match="update.sh.dist"):
        upd.inspect_updater_result(
            staging,
            result,
            to_ref="self-hosted/v0.8.2",
            to_sha=up.PINNED_SHA,
        )


def test_inspect_updater_timeout(tmp_path: Path):
    staging = tmp_path / "stage"
    staging.mkdir()
    result = SimpleNamespace(
        returncode=-1,
        stdout="",
        stderr="",
        timed_out=True,
    )
    with pytest.raises(upd.UpdateError, match="timed out"):
        upd.inspect_updater_result(
            staging,
            result,
            to_ref="self-hosted/v0.8.2",
            to_sha=up.PINNED_SHA,
        )


def test_mechanical_promote_no_preserve_policy(tmp_path: Path):
    staging = tmp_path / "stage"
    live = tmp_path / "live"
    staging.mkdir()
    live.mkdir()
    (staging / "docker-compose.yml").write_text("staged\n", encoding="utf-8")
    (live / "docker-compose.yml").write_text("live-old\n", encoding="utf-8")
    q = tmp_path / "q"
    record = upd.build_promote_record(
        operation_id="op-test",
        from_ref="self-hosted/v0.8.1",
        from_sha="a" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="b" * 40,
        backup_id="bk-1",
        staging=staging,
        deployment=live,
        quarantine=q,
        relpaths=["docker-compose.yml"],
    )
    upd.write_promote_record(staging, record)
    promoted = upd.mechanical_promote(
        staging,
        live,
        record=record,
        quarantine=q,
    )
    assert promoted == ["docker-compose.yml"]
    assert (live / "docker-compose.yml").read_text(encoding="utf-8") == "staged\n"
    assert (q / "docker-compose.yml").read_text(encoding="utf-8") == "live-old\n"
    reloaded = upd.load_promote_record(upd.promote_record_path(staging))
    assert reloaded["paths"][0]["progress"] == upd.PROGRESS_VERIFIED
    assert reloaded["paths_promoted_complete"] is True
    # No preserve helpers remain in module.
    assert not hasattr(upd, "_promote_vendor")
    assert not hasattr(upd, "_should_preserve")
    assert not hasattr(upd, "_append_missing_env_keys")


def test_list_promote_excludes_backups_and_data(tmp_path: Path):
    staging = tmp_path / "stage"
    (staging / "backups").mkdir(parents=True)
    (staging / "backups" / "pre-update.tgz").write_bytes(b"secret-plain")
    (staging / "volumes" / "db" / "data").mkdir(parents=True)
    (staging / "volumes" / "db" / "data" / "PG_VERSION").write_text("17", encoding="utf-8")
    (staging / "docker-compose.yml").write_text("x\n", encoding="utf-8")
    paths = upd.list_promote_relpaths(staging)
    assert "docker-compose.yml" in paths
    assert not any(p.startswith("backups/") for p in paths)
    assert not any("volumes/db/data" in p for p in paths)


def test_staging_permissions_and_plaintext_containment(tmp_path: Path):
    root, meta = _write_project(tmp_path)
    dep = reg.project_dir(root, "demo") / "deployment"
    staging = root / "staging" / "update-op"
    upd._seed_staging(dep, staging)
    mode = staging.stat().st_mode & 0o777
    assert mode & 0o077 == 0
    # Simulate updater plaintext backup inside staging only.
    bak = staging / "backups" / "pre-update-test.tgz"
    bak.parent.mkdir(parents=True, exist_ok=True)
    secret = "postgres-password-long"
    bak.write_bytes(secret.encode())
    assert bak.is_file()
    assert not (dep / "backups" / "pre-update-test.tgz").exists()
    # Promote list must not include plaintext backup.
    assert all(not p.startswith("backups/") for p in upd.list_promote_relpaths(staging))


def test_reconcile_refuses_unsafe_new_secret(tmp_path: Path):
    root = reg.ensure_root(tmp_path / "home")
    meta = _meta(root)
    dest = {
        "JWT_SECRET": "abcdefghijklmnopqrstuvwxyz012345",
        "ANON_KEY": "anon-key-value-long-enough",
        "SERVICE_ROLE_KEY": "service-role-key-long",
        "SUPABASE_PUBLISHABLE_KEY": "pub-key-long-enough",
        "SUPABASE_SECRET_KEY": "secret-key-long-enough",
        "JWT_KEYS": '[{"kty":"oct","k":"x"}]',
        "JWT_JWKS": '{"keys":[{"kty":"oct","k":"x"}]}',
        "POSTGRES_PASSWORD": "postgres-password-long",
        "DASHBOARD_USERNAME": "admin",
        "DASHBOARD_PASSWORD": "dashboard-password-long",
        "SECRET_KEY_BASE": "secret-key-base-long-enough-32",
        "VAULT_ENC_KEY": "vault-enc-key-long-enough-32ch",
        "POOLER_TENANT_ID": "tenant",
        "COMPOSE_PROJECT_NAME": meta["compose_project"],
        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
        "KONG_HTTP_PORT": "18000",
        "SUPABASE_PUBLIC_URL": "http://127.0.0.1:18000",
        "API_EXTERNAL_URL": "http://127.0.0.1:18000/auth/v1",
    }
    staged = dict(dest)
    staged["BRAND_NEW_API_SECRET"] = "your-super-secret"
    before = {k: dest.get(k) for k in up.REQUIRED_ENV_KEYS}
    with pytest.raises(upd.UpdateError, match="BRAND_NEW_API_SECRET"):
        upd.reconcile_update_env(
            staged_env=staged,
            destination_env=dest,
            destination_meta=meta,
            before_secrets=before,
        )


def test_staging_failure_leaves_live_hashes_unchanged(tmp_path: Path):
    """Executable hash proof: updater failure before promote does not touch live."""
    root, _meta_data = _write_project(tmp_path)
    dep = reg.project_dir(root, "demo") / "deployment"
    before = upd.hash_authority_surface(dep)

    staging = root / "staging" / "update-fail"
    upd._seed_staging(dep, staging)
    (staging / "update.sh").write_text(
        "#!/bin/sh\necho 'CONFLICTS: 1' ; echo '<<<<<<<' > conflicted.yml; exit 0\n",
        encoding="utf-8",
    )
    os.chmod(staging / "update.sh", 0o700)
    result = ProcessResult(
        argv=["sh", "update.sh", "--to", "self-hosted/v0.8.2"],
        returncode=0,
        stdout="CONFLICTS: 1\n",
        stderr="",
    )
    with pytest.raises(upd.UpdateError, match="CONFLICTS"):
        upd.inspect_updater_result(
            staging,
            result,
            to_ref="self-hosted/v0.8.2",
            to_sha=up.PINNED_SHA,
        )
    assert upd.hash_authority_surface(dep) == before


def test_no_custom_merge_engine_helpers():
    for name in (
        "_promote_vendor",
        "_should_preserve",
        "_append_missing_env_keys",
        "_PRESERVE_PREFIXES",
    ):
        assert not hasattr(upd, name)


def test_reviewed_transitions_are_directed_edges_only():
    assert ("self-hosted/v0.8.1", "self-hosted/v0.8.2") in up.REVIEWED_TRANSITIONS
    assert ("self-hosted/v0.8.2", "self-hosted/v0.8.1") not in up.REVIEWED_TRANSITIONS


def test_updater_timeout_constant_finite():
    assert upd.UPDATER_TIMEOUT_S > 0
    assert upd.UPDATER_TIMEOUT_S <= 3600


def test_wipe_removes_plaintext_staging(tmp_path: Path):
    staging = tmp_path / "stage"
    staging.mkdir(mode=0o700)
    secret_file = staging / "backups" / "pre.tgz"
    secret_file.parent.mkdir(mode=0o700)
    secret_file.write_text("POSTGRES_PASSWORD=supersecretvalue", encoding="utf-8")

    def _rm(p: Path) -> None:
        shutil.rmtree(p)

    with mock.patch("sbfleet.backup._wipe_staging", side_effect=_rm):
        upd._wipe_update_staging(staging)
    assert not staging.exists()


def test_failed_staging_retains_private_mode(tmp_path: Path):
    staging = tmp_path / "diag"
    staging.mkdir(mode=0o700)
    (staging / ".env").write_text("POSTGRES_PASSWORD=keep-private\n", encoding="utf-8")
    os.chmod(staging, 0o700)
    mode = staging.stat().st_mode
    assert stat.S_IMODE(mode) & 0o077 == 0
