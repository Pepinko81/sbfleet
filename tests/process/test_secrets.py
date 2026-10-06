"""Module tests."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import upstream as up
from sbfleet.process import ProcessResult


@pytest.fixture()
def vendor_docker(tmp_path: Path) -> Path:
    """Minimal vendor tree sufficient for mocked generators; real tests use cache."""
    docker = tmp_path / "vendor" / "docker"
    docker.mkdir(parents=True)
    (docker / ".env.example").write_text(
        "\n".join(
            [
                "JWT_SECRET=your-super-secret-jwt-token-with-at-least-32-characters-long",
                "ANON_KEY=placeholder",
                "SERVICE_ROLE_KEY=placeholder",
                "SUPABASE_PUBLISHABLE_KEY=",
                "SUPABASE_SECRET_KEY=",
                "JWT_KEYS=",
                "JWT_JWKS=",
                "POSTGRES_PASSWORD=your-super-secret-and-long-postgres-password",
                "DASHBOARD_USERNAME=supabase",
                "DASHBOARD_PASSWORD=this_password_is_insecure_and_should_be_updated",
                "SECRET_KEY_BASE=",
                "VAULT_ENC_KEY=",
                "POOLER_TENANT_ID=your-tenant-id",
                "COMPOSE_FILE=docker-compose.yml",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (docker / "docker-compose.yml").write_text("services: {}\n" + ("c" * 120), encoding="utf-8")
    utils = docker / "utils"
    utils.mkdir()
    (utils / "generate-keys.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (utils / "add-new-auth-keys.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(utils / "generate-keys.sh", 0o700)
    os.chmod(utils / "add-new-auth-keys.sh", 0o700)
    return docker


def _valid_env(project_id: str) -> dict[str, str]:
    jwks = json.dumps({"keys": [{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}]})
    keys = json.dumps([{"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "c"}])
    return {
        "JWT_SECRET": "a" * 32,
        "ANON_KEY": "anon-" + project_id,
        "SERVICE_ROLE_KEY": "service-" + project_id,
        "SUPABASE_PUBLISHABLE_KEY": "pub-" + project_id,
        "SUPABASE_SECRET_KEY": "sec-" + project_id,
        "JWT_KEYS": keys,
        "JWT_JWKS": jwks,
        "POSTGRES_PASSWORD": "p" * 32,
        "DASHBOARD_USERNAME": "supabase",
        "DASHBOARD_PASSWORD": "d" * 32,
        "SECRET_KEY_BASE": "s" * 32,
        "VAULT_ENC_KEY": "v" * 32,
        "POOLER_TENANT_ID": "tenant",
    }


def test_parse_dotenv_rejects_duplicates() -> None:
    with pytest.raises(up.UpstreamError, match="duplicate"):
        up.parse_dotenv("A=1\nA=2\n")


def test_parse_dotenv_rejects_malformed() -> None:
    with pytest.raises(up.UpstreamError):
        up.parse_dotenv("not-a-pair\n")


def test_missing_node_refuses_docker_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def _which(name: str):
        return None if name == "node" else "/usr/bin/openssl"

    monkeypatch.setattr(shutil, "which", _which)
    with pytest.raises(up.UpstreamError, match="Docker fallback refused"):
        up.require_local_node()


def test_generator_midway_failure(vendor_docker: Path, tmp_path: Path) -> None:
    calls = {"n": 0}

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            # First script "succeeds" but we still need .env — simulate ok
            return ProcessResult(argv=list(argv), returncode=0, stdout="ok", stderr="")
        return ProcessResult(argv=list(argv), returncode=1, stdout="", stderr="boom")

    with (
        mock.patch("sbfleet.upstream.require_local_node", return_value="/usr/bin/node"),
        mock.patch("sbfleet.upstream.run", side_effect=fake_run),
    ):
        with pytest.raises(up.UpstreamError, match="secret generator failed"):
            up.generate_secrets_in_scratch(
                vendor_docker,
                tmp_path / "scratch",
                project_id=str(uuid.uuid4()),
                public_url="http://127.0.0.1:20000",
                gateway_port=20000,
            )


def test_resume_refuses_regenerate(tmp_path: Path) -> None:
    dep = tmp_path / "dep"
    dep.mkdir()
    env = _valid_env(str(uuid.uuid4()))
    (dep / ".env").write_text(up.dump_dotenv(env), encoding="utf-8")
    src = tmp_path / "src.env"
    src.write_text(up.dump_dotenv(env), encoding="utf-8")
    with pytest.raises(up.UpstreamError, match="already exists"):
        up.install_env_only(src, dep)


def test_validate_rejects_placeholder_json() -> None:
    env = _valid_env(str(uuid.uuid4()))
    env["JWT_JWKS"] = "not-json"
    with pytest.raises(up.UpstreamError):
        up.validate_generated_env(env)


def test_fleet_defaults_unique_dashboard() -> None:
    pid = "11111111-2222-4333-8444-555555555555"
    env = up.apply_fleet_env_defaults(
        _valid_env(pid),
        project_id=pid,
        public_url="http://127.0.0.1:21000",
        gateway_port=21000,
    )
    assert env["DASHBOARD_USERNAME"] == "sb_111111112222"
    assert env["POOLER_TENANT_ID"] == pid.replace("-", "")
    assert env["ENABLE_EMAIL_SIGNUP"] == "false"
    assert env["ENABLE_PHONE_SIGNUP"] == "false"
    assert env["SUPABASE_PUBLIC_URL"] == "http://127.0.0.1:21000"
    assert env["API_EXTERNAL_URL"] == "http://127.0.0.1:21000/auth/v1"
    assert env["SITE_URL"] == "http://127.0.0.1:21000"
    assert env["STUDIO_DEFAULT_ORGANIZATION"] == "Default Organization"
    assert env["STUDIO_DEFAULT_PROJECT"] == "Default Project"
    assert env["GOOGLE_ENABLED"] == "false"


@pytest.mark.skipif(shutil.which("node") is None, reason="node required")
def test_real_generators_two_projects_differ(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    cache: Path | None = None
    try:
        cache = up.materialize_cache(root)
    except up.UpstreamError:
        # Optional planning reference clone — convenience only.
        ref = Path.home() / ".cache/sbfleet/upstream/supabase"
        docker = ref / "docker"
        if not docker.is_dir():
            pytest.skip("upstream fetch unavailable and no reference clone")
        cache = root / "cache" / "upstream" / up.PINNED_SHA
        cache.mkdir(parents=True)
        shutil.copytree(docker, cache / "docker", symlinks=False)
        from helpers_upstream import write_cache_marker

        write_cache_marker(cache)
        up.verify_cache(cache)
    assert cache is not None
    vendor = cache / "docker"
    compose_before = up.vendor_file_digest(vendor, "docker-compose.yml")
    envs = []
    for i in range(2):
        pid = str(uuid.uuid4())
        scratch = tmp_path / f"scratch-{i}"
        env = up.generate_secrets_in_scratch(
            vendor,
            scratch,
            project_id=pid,
            public_url=f"http://127.0.0.1:{22000 + i}",
            gateway_port=22000 + i,
        )
        envs.append(env)
        assert not list(scratch.rglob("*.old"))
        for p in scratch.rglob("*"):
            if p.is_file() and p.name.endswith(".log"):
                raise AssertionError(f"capture log persisted: {p}")
            if p.name == "keys.txt":
                raise AssertionError("keys.txt must not persist")
    assert envs[0]["JWT_SECRET"] != envs[1]["JWT_SECRET"]
    assert envs[0]["ANON_KEY"] != envs[1]["ANON_KEY"]
    assert envs[0]["POSTGRES_PASSWORD"] != envs[1]["POSTGRES_PASSWORD"]
    assert envs[0]["DASHBOARD_USERNAME"] != envs[1]["DASHBOARD_USERNAME"]
    assert up.vendor_file_digest(vendor, "docker-compose.yml") == compose_before
