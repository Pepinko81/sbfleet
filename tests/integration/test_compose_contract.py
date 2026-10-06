"""Module tests."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet import upstream as up


def _seed_cache(root: Path) -> Path:
    try:
        return up.materialize_cache(root)
    except up.UpstreamError:
        ref = Path.home() / ".cache/sbfleet/upstream/supabase/docker"
        if not ref.is_dir():
            pytest.skip("no upstream docker available")
        cache = root / "cache" / "upstream" / up.PINNED_SHA
        cache.mkdir(parents=True)
        shutil.copytree(ref, cache / "docker", symlinks=False)
        from helpers_upstream import write_cache_marker

        write_cache_marker(cache)
        up.verify_cache(cache)
        return cache


@pytest.mark.docker
def test_compose_contract_two_projects(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker unavailable")
    if not c.supports_override_tag():
        pytest.fail("Compose !override unsupported — fail closed")

    home = reg.ensure_root(tmp_path / "home")
    cache = _seed_cache(home)
    vendor = cache / "docker"
    fid = reg.fleet_id(home)

    for i, slug in enumerate(("alpha", "beta")):
        pid = str(uuid.uuid4())
        cp = reg.compose_project_name(fid, pid)
        ports = {
            "gateway": 21000 + i * 10,
            "db_direct": 21001 + i * 10,
            "pooler_session": 21002 + i * 10,
            "pooler_transaction": 21003 + i * 10,
        }
        dep = tmp_path / f"dep-{slug}"
        up.copy_vendor_docker(cache, dep)
        scratch = tmp_path / f"scratch-{slug}"
        env = up.generate_secrets_in_scratch(
            vendor,
            scratch,
            project_id=pid,
            public_url=f"http://127.0.0.1:{ports['gateway']}",
            gateway_port=ports["gateway"],
        )
        up.install_env_only(scratch / ".env", dep)
        parsed = up.parse_dotenv((dep / ".env").read_text(encoding="utf-8"))
        parsed["COMPOSE_PROJECT_NAME"] = cp
        (dep / ".env").write_text(up.dump_dotenv(parsed), encoding="utf-8")
        os.chmod(dep / ".env", 0o600)

        override = c.render_override(
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            gateway_port=ports["gateway"],
            db_direct_port=ports["db_direct"],
            pooler_session_port=ports["pooler_session"],
            pooler_transaction_port=ports["pooler_transaction"],
        )
        c.write_override(dep, override)
        config = c.compose_config_json(dep, compose_project=cp, env=parsed)
        c.validate_resolved_config(
            config,
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            gateway_port=ports["gateway"],
            db_direct_port=ports["db_direct"],
            pooler_session_port=ports["pooler_session"],
            pooler_transaction_port=ports["pooler_transaction"],
            deployment=dep,
            allowed_bind_roots=[dep],
        )
        for svc in config["services"].values():
            for p in svc.get("ports") or []:
                assert p.get("host_ip") == "127.0.0.1"
        # silence unused
        assert slug
        assert env["JWT_SECRET"]
