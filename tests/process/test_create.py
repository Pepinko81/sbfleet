"""Module tests."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from sbfleet import projects as proj
from sbfleet import registry as reg
from sbfleet import upstream as up


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _fake_pipeline(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    cache = home / "cache" / "upstream" / up.PINNED_SHA
    docker = cache / "docker"
    docker.mkdir(parents=True)
    (docker / "docker-compose.yml").write_text("services: {}\n" + ("x" * 120))
    (docker / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (docker / ".env.example").write_text("JWT_SECRET=x\n", encoding="utf-8")
    import os

    from helpers_upstream import write_cache_marker

    write_cache_marker(cache)
    os.chmod(docker / "run.sh", 0o700)

    monkeypatch.setattr(up, "materialize_cache", lambda root, **k: cache)

    def fake_copy(cache_p, deployment, **k):  # type: ignore[no-untyped-def]
        deployment.mkdir(parents=True, exist_ok=True)
        for name in ("docker-compose.yml", "run.sh", ".env.example"):
            (deployment / name).write_bytes((docker / name).read_bytes())

    monkeypatch.setattr(up, "copy_vendor_docker", fake_copy)

    def fake_secrets(vendor, scratch, **k):  # type: ignore[no-untyped-def]
        import json as js

        scratch.mkdir(parents=True)
        env = {
            "JWT_SECRET": "j" * 32,
            "ANON_KEY": "anon-" + str(uuid.uuid4()),
            "SERVICE_ROLE_KEY": "svc-" + str(uuid.uuid4()),
            "SUPABASE_PUBLISHABLE_KEY": "pub-" + str(uuid.uuid4()),
            "SUPABASE_SECRET_KEY": "sec-" + str(uuid.uuid4()),
            "JWT_KEYS": js.dumps([{"kty": "EC"}]),
            "JWT_JWKS": js.dumps({"keys": [{"kty": "EC"}]}),
            "POSTGRES_PASSWORD": "p" * 32,
            "DASHBOARD_USERNAME": "sb_x",
            "DASHBOARD_PASSWORD": "d" * 32,
            "SECRET_KEY_BASE": "s" * 32,
            "VAULT_ENC_KEY": "v" * 32,
            "POOLER_TENANT_ID": "t",
            "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
            "COMPOSE_PATH_SEPARATOR": ":",
        }
        (scratch / ".env").write_text(up.dump_dotenv(env), encoding="utf-8")
        return env

    monkeypatch.setattr(up, "generate_secrets_in_scratch", fake_secrets)

    def fake_install(src, dep):  # type: ignore[no-untyped-def]
        dest = Path(dep) / ".env"
        dest.write_text(Path(src).read_text(encoding="utf-8"), encoding="utf-8")
        return dest

    monkeypatch.setattr(up, "install_env_only", fake_install)

    from sbfleet import compose as c

    monkeypatch.setattr(c, "supports_override_tag", lambda: True)
    monkeypatch.setattr(
        c,
        "compose_config_json",
        lambda *a, **k: {
            "services": {
                s: {
                    "container_name": f"x-{s}",
                    "labels": {
                        "io.sbfleet.fleet": k.get("env", {}).get("F") or "f",
                        "io.sbfleet.project": "p",
                    },
                    "ports": [],
                    "networks": {"default": {"aliases": [c.REALTIME_ALIAS]}}
                    if s == "realtime"
                    else {},
                }
                for s in c.STANDARD_SERVICES
            },
            "networks": {"default": {}},
            "volumes": {"db-config": {}, "deno-cache": {}},
        },
    )

    def fake_validate(config, **kwargs):  # type: ignore[no-untyped-def]
        # Patch labels to match kwargs for validator if we call real one — skip by no-op
        return None

    monkeypatch.setattr(c, "validate_resolved_config", fake_validate)


def test_create_no_start_stopped(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_pipeline(monkeypatch, home)
    meta = proj.create_project(home, "demo", display_name="Demo")
    assert meta["creation_complete"] is True
    assert meta["slug"] == "demo"
    loaded = reg.read_project(home, "demo")
    assert loaded["ports"]["gateway"] >= 20000


def test_complete_slug_refuses_overwrite(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_pipeline(monkeypatch, home)
    proj.create_project(home, "demo")
    with pytest.raises(proj.ProjectError) as ei:
        proj.create_project(home, "demo")
    assert ei.value.code == 5


def test_resume_preserves_ports_and_keys(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_pipeline(monkeypatch, home)
    # Create incomplete row manually then resume
    ports, held = reg.allocate_ports(home)
    reg.release_held_sockets(held)
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": "partial",
        "display_name": "Partial",
        "created_at": "2026-09-26T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": ports,
        "domain": None,
        "public_url": f"http://127.0.0.1:{ports['gateway']}",
        "upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA},
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": False,
    }
    reg.write_project(home, meta)
    # Put .env in place to prove no regenerate
    dep = reg.project_dir(home, "partial") / "deployment"
    dep.mkdir(parents=True)
    (dep / "docker-compose.yml").write_text("services: {}\n" + ("x" * 120))
    (dep / "run.sh").write_text("#!/bin/sh\n")
    secret = "preserve-me-secret-value-32chars!!"
    env = {
        "JWT_SECRET": secret,
        "ANON_KEY": "anon-keep",
        "SERVICE_ROLE_KEY": "svc-keep",
        "SUPABASE_PUBLISHABLE_KEY": "pub-keep",
        "SUPABASE_SECRET_KEY": "sec-keep",
        "JWT_KEYS": '[{"kty":"EC"}]',
        "JWT_JWKS": '{"keys":[{"kty":"EC"}]}',
        "POSTGRES_PASSWORD": "p" * 32,
        "DASHBOARD_USERNAME": "sb_x",
        "DASHBOARD_PASSWORD": "d" * 32,
        "SECRET_KEY_BASE": "s" * 32,
        "VAULT_ENC_KEY": "v" * 32,
        "POOLER_TENANT_ID": "t",
    }
    (dep / ".env").write_text(up.dump_dotenv(env), encoding="utf-8")
    out = proj.create_project(home, "partial", resume=True)
    assert out["creation_complete"] is True
    assert out["ports"] == ports
    assert secret in (dep / ".env").read_text(encoding="utf-8")


def test_create_start_requires_lifecycle(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_pipeline(monkeypatch, home)

    def boom_start(*a, **k):  # type: ignore[no-untyped-def]
        raise proj.ProjectError("start failed in test", code=1)

    monkeypatch.setattr(proj, "start_project", boom_start)
    with pytest.raises(proj.ProjectError):
        proj.create_project(home, "x", start=True)
    meta = reg.read_project(home, "x")
    assert meta.get("creation_complete") is False
    assert (meta.get("create_intent") or {}).get("requested_start") is True


def test_failure_after_reserve_visible(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_pipeline(monkeypatch, home)

    def boom(*a, **k):  # type: ignore[no-untyped-def]
        raise RuntimeError("inject")

    monkeypatch.setattr(up, "materialize_cache", boom)
    with pytest.raises(proj.ProjectError):
        proj.create_project(home, "boom")
    rows = reg.list_projects(home)
    assert any(r.slug == "boom" for r in rows)
    meta = rows[0].data
    assert meta.get("creation_complete") is False
