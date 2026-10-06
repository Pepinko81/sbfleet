"""Sandbox config authority."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import sandbox as sb
from sbfleet.sandbox_adoption import (
    SandboxAdoptionError,
    SandboxLocks,
    canonicalize_app_root,
    commit_adoption_pair,
    index_path_for,
    journal_path,
    new_adoption,
    path_hash_short,
    project_id_index_key,
    reconcile_adoption_index,
    state_dir_for,
)
from sbfleet.sandbox_authority import (
    SandboxAuthorityError,
    audit_dotenv,
    audit_linked_remote_state,
    child_env,
    parse_dotenv_keys,
    prove_network_owned,
)
from sbfleet.sandbox_config import (
    SandboxConfigError,
    assert_local_url,
    classify_fingerprint_drift,
    is_loopback_host,
    parse_sandbox_config,
    validate_migration_mode,
)


def _write_config(
    app: Path,
    project_id: str,
    *,
    api_port: int = 54321,
    migrations_enabled: bool = True,
    seed_enabled: bool = True,
    extra: str = "",
) -> None:
    (app / "supabase").mkdir(parents=True, exist_ok=True)
    (app / "supabase" / "config.toml").write_text(
        f'project_id = "{project_id}"\n'
        f"[api]\nport = {api_port}\n"
        f"[db]\nport = 54322\nmajor_version = 15\n"
        f"[db.migrations]\nenabled = {'true' if migrations_enabled else 'false'}\n"
        f"[db.seed]\nenabled = {'true' if seed_enabled else 'false'}\n"
        f"[studio]\nport = 54323\n"
        f"{extra}",
        encoding="utf-8",
    )


def test_toml_rejects_regex_false_positive(tmp_path: Path) -> None:
    """Syntax that fooled old regex must not be accepted as project_id."""
    (tmp_path / "supabase").mkdir()
    # Comment / spoof line that regex would match; real project_id missing type-valid value
    (tmp_path / "supabase" / "config.toml").write_text(
        '# project_id = "sbfleet-dev-fake"\nnot_project = "sbfleet-dev-x"\nproject_id = 12345\n',
        encoding="utf-8",
    )
    with pytest.raises(SandboxConfigError, match="non-empty string"):
        parse_sandbox_config(tmp_path)


def test_toml_malformed(tmp_path: Path) -> None:
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text(
        'project_id = "sbfleet-dev-x"\n[bad\n', encoding="utf-8"
    )
    with pytest.raises(SandboxConfigError, match="malformed"):
        parse_sandbox_config(tmp_path)


def test_toml_missing_project_id(tmp_path: Path) -> None:
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text("[api]\nport = 1\n", encoding="utf-8")
    with pytest.raises(SandboxConfigError, match="missing project_id"):
        parse_sandbox_config(tmp_path)


def test_fingerprint_stable_and_drift(tmp_path: Path) -> None:
    _write_config(tmp_path, "sbfleet-test-aaaa")
    a = parse_sandbox_config(tmp_path)
    b = parse_sandbox_config(tmp_path)
    assert a.fingerprint == b.fingerprint
    _write_config(tmp_path, "sbfleet-test-aaaa", api_port=54329)
    c = parse_sandbox_config(tmp_path)
    assert c.fingerprint != a.fingerprint
    drift = classify_fingerprint_drift(a.fingerprint_fields, c.fingerprint_fields)
    assert any("api.port" in line for line in drift)


def test_url_locality_rejects_spoofs() -> None:
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("localhost")
    assert is_loopback_host("::1")
    assert not is_loopback_host("localhost.example.com")
    assert not is_loopback_host("127.0.0.1.example.com")
    assert not is_loopback_host("8.8.8.8")
    assert not is_loopback_host("example.com")
    with pytest.raises(SandboxConfigError):
        assert_local_url("http://localhost.example.com:54321", context="API")
    with pytest.raises(SandboxConfigError):
        assert_local_url("http://127.0.0.1.example.com", context="API")
    with pytest.raises(SandboxConfigError):
        assert_local_url("http://8.8.8.8:54321", context="API")
    assert_local_url("http://127.0.0.1:54321", context="API")
    assert_local_url("postgresql://postgres:x@127.0.0.1:54322/postgres", context="DB")


def test_external_mode_allows_migration_files(tmp_path: Path) -> None:
    _write_config(
        tmp_path,
        "sbfleet-test-bbbb",
        migrations_enabled=False,
        seed_enabled=False,
    )
    (tmp_path / "supabase" / "migrations").mkdir()
    (tmp_path / "supabase" / "migrations" / "001_app.sql").write_text(
        "select 1;\n", encoding="utf-8"
    )
    cfg = parse_sandbox_config(tmp_path)
    validate_migration_mode(cfg, "external")  # must not require empty dirs


def test_external_mode_requires_disabled_auto(tmp_path: Path) -> None:
    _write_config(tmp_path, "sbfleet-test-cccc")
    cfg = parse_sandbox_config(tmp_path)
    with pytest.raises(SandboxConfigError, match="enabled = false"):
        validate_migration_mode(cfg, "external")


def test_canonical_root_symlink_collapse(tmp_path: Path) -> None:
    real = tmp_path / "realapp"
    real.mkdir()
    link = tmp_path / "alias"
    link.symlink_to(real)
    assert canonicalize_app_root(link) == real.resolve()
    assert path_hash_short(canonicalize_app_root(link)) == path_hash_short(real.resolve())


def test_refuse_fleet_path(tmp_path: Path) -> None:
    home = tmp_path / "fleet"
    banned = home / "projects" / "x" / "deployment"
    banned.mkdir(parents=True)
    with pytest.raises(SandboxAdoptionError, match="fleet"):
        canonicalize_app_root(banned, fleet_home=home)


def test_project_id_index_safe_encoding() -> None:
    evil = "sbfleet-dev-../../etc/passwd"
    key = project_id_index_key(evil)
    assert "/" not in key
    assert ".." not in key
    assert len(key) == 64


def test_adoption_index_pair_and_disagreement(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    canonical = canonicalize_app_root(app, fleet_home=home)
    rec = new_adoption(
        canonical=canonical,
        cli_project_id="sbfleet-test-pair1",
        config_fingerprint="abc",
        fingerprint_fields={"project_id": "sbfleet-test-pair1"},
        cli_version="2.118.0",
        migration_mode="supabase",
    )
    with SandboxLocks(home, canonical):
        commit_adoption_pair(home, rec)
        loaded = reconcile_adoption_index(home, canonical, cli_project_id=rec.cli_project_id)
        assert loaded is not None
        assert loaded.sandbox_uuid == rec.sandbox_uuid

        # Index missing → fail closed
        index_path_for(home, rec.cli_project_id).unlink()
        with pytest.raises(SandboxAdoptionError, match="index missing"):
            reconcile_adoption_index(home, canonical, cli_project_id=rec.cli_project_id)


def test_interrupted_journal_fail_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app2"
    app.mkdir()
    canonical = canonicalize_app_root(app, fleet_home=home)
    journal_path(home).parent.mkdir(parents=True, exist_ok=True)
    journal_path(home).write_text('{"phase":"commit"}\n', encoding="utf-8")
    with SandboxLocks(home, canonical):
        with pytest.raises(SandboxAdoptionError, match="journal"):
            reconcile_adoption_index(home, canonical, cli_project_id="sbfleet-test-j")


def test_duplicate_project_id_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    ca = canonicalize_app_root(a, fleet_home=home)
    cb = canonicalize_app_root(b, fleet_home=home)
    pid = "sbfleet-test-dup1"
    rec = new_adoption(
        canonical=ca,
        cli_project_id=pid,
        config_fingerprint="x",
        fingerprint_fields={},
        cli_version="2.118.0",
        migration_mode="supabase",
    )
    with SandboxLocks(home, ca):
        commit_adoption_pair(home, rec)
    with SandboxLocks(home, cb):
        with pytest.raises(SandboxAdoptionError, match="already adopted"):
            reconcile_adoption_index(home, cb, cli_project_id=pid)


def test_dotenv_export_form_refused(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text('export SUPABASE_ACCESS_TOKEN="tok"\n', encoding="utf-8")
    with pytest.raises(SandboxAuthorityError):
        audit_dotenv(tmp_path)
    parsed = parse_dotenv_keys('export SUPABASE_ACCESS_TOKEN="tok"\n')
    assert parsed["SUPABASE_ACCESS_TOKEN"] == "tok"


def test_linked_project_ref_refused(tmp_path: Path) -> None:
    temp = tmp_path / "supabase" / ".temp"
    temp.mkdir(parents=True)
    (temp / "project-ref").write_text("abcdefghijklmnopqrst\n", encoding="utf-8")
    cli_home = tmp_path / "cli-home"
    cli_home.mkdir()
    with pytest.raises(SandboxAuthorityError, match="linked"):
        audit_linked_remote_state(tmp_path, False, cli_home)


def test_child_env_allowlist_no_inherit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SUPABASE_ACCESS_TOKEN", "leak")
    monkeypatch.setenv("DATABASE_URL", "postgres://evil")
    monkeypatch.setenv("DOCKER_HOST", "tcp://evil:2375")
    env = child_env(tmp_path)
    assert "DOCKER_HOST" not in env
    assert env["SUPABASE_ACCESS_TOKEN"] == "invalid-token-sentinel"
    assert "DATABASE_URL" not in env


def test_network_ownership_mismatch() -> None:
    fake = [
        {
            "Id": "abc",
            "Driver": "bridge",
            "Scope": "local",
            "Labels": {"io.sbfleet.sandbox": "hash1", "io.sbfleet.sandbox_uuid": "uuid1"},
            "Options": {"com.docker.network.bridge.host_binding_ipv4": "0.0.0.0"},
        }
    ]
    with mock.patch("sbfleet.sandbox_authority._docker_json", return_value=fake):
        with pytest.raises(SandboxAuthorityError, match="host_binding"):
            prove_network_owned("abc", path_hash="hash1", sandbox_uuid="uuid1")


def test_forbidden_dotenv_compat() -> None:
    # historical unit test surface
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / ".env").write_text("SUPABASE_ACCESS_TOKEN=realtoken\n", encoding="utf-8")
        with pytest.raises(sb.SandboxError):
            sb.audit_dotenv(p)


def test_cli_pin_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sb, "_cli_version", lambda: "2.54.11")
    with pytest.raises(sb.SandboxError, match="incompatible"):
        sb.require_pinned_cli()


def test_path_hash_stable(tmp_path: Path) -> None:
    assert sb.path_hash(tmp_path) == sb.path_hash(tmp_path)


def test_short_hash_collision_detection(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    canonical = canonicalize_app_root(app, fleet_home=home)
    phash = path_hash_short(canonical)
    # Plant adoption with different canonical under same short hash dir
    state = state_dir_for(home, canonical)
    state.mkdir(parents=True)
    (state / "adoption.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sandbox_uuid": "u",
                "canonical_app_root": str(tmp_path / "other"),
                "path_hash": phash,
                "cli_project_id": "sbfleet-test-x",
                "config_fingerprint": "f",
                "fingerprint_fields": {},
                "cli_version": "2.118.0",
                "migration_mode": "supabase",
                "network_id": None,
                "network_name": f"sbfleet-sb-{phash}",
                "owned_resources": {},
                "adopted_at": "t",
                "updated_at": "t",
            }
        ),
        encoding="utf-8",
    )
    with SandboxLocks(home, canonical):
        with pytest.raises(SandboxAdoptionError, match="collision"):
            reconcile_adoption_index(home, canonical, cli_project_id="sbfleet-test-x")
