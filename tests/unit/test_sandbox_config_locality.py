"""Sandbox config locality."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sbfleet.sandbox_authority import (
    SandboxAuthorityError,
    invent_owned_resources,
    parse_dotenv_keys,
    status_endpoints_local,
)
from sbfleet.sandbox_config import (
    SandboxConfigError,
    assert_local_url,
    validate_external_paths,
)

_NET_ID = "a" * 64


def test_malformed_dotenv_refuses() -> None:
    with pytest.raises(SandboxAuthorityError, match="malformed|unsupported"):
        parse_dotenv_keys("not a valid assignment\n")
    with pytest.raises(SandboxAuthorityError, match="quoting"):
        parse_dotenv_keys('FOO="unclosed\n')
    assert parse_dotenv_keys("# comment\nBAR=ok\nexport BAZ=1\n") == {
        "BAR": "ok",
        "BAZ": "1",
    }


def test_dangerous_pg_and_docker_vars() -> None:
    from sbfleet.sandbox_authority import DANGEROUS_ENV_KEYS

    for key in ("PGHOST", "PGHOSTADDR", "PGSERVICE", "DOCKER_CERT_PATH", "COMPOSE_FILE"):
        assert key in DANGEROUS_ENV_KEYS or key.startswith("PG") or key.startswith("DOCKER")


def test_external_function_path_refused(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    outside = tmp_path / "outside" / "index.ts"
    outside.parent.mkdir()
    outside.write_text("Deno.serve(() => new Response('x'))\n", encoding="utf-8")
    data = {
        "functions": {
            "hello": {"entrypoint": str(outside)},
        }
    }
    with pytest.raises(SandboxConfigError, match="escapes"):
        validate_external_paths(app, data)


def test_symlink_function_escape_refused(tmp_path: Path) -> None:
    app = tmp_path / "app"
    (app / "supabase").mkdir(parents=True)
    outside = tmp_path / "secret.ts"
    outside.write_text("x", encoding="utf-8")
    link = app / "escape.ts"
    link.symlink_to(outside)
    data = {"functions": {"hello": {"entrypoint": "./escape.ts"}}}
    with pytest.raises(SandboxConfigError, match="escapes|symlink"):
        validate_external_paths(app, data)


def test_http_userinfo_refused() -> None:
    with pytest.raises(SandboxConfigError, match="userinfo"):
        assert_local_url("http://user:pass@127.0.0.1:54323", context="STUDIO", kind="http")
    assert_local_url("http://127.0.0.1:54323", context="STUDIO", kind="http")


def test_postgres_normal_cli_url_accepted() -> None:
    # Pinned CLI 2.118.0 status DB_URL form: no query string.
    url = "postgresql://postgres:postgres@127.0.0.1:54322/postgres"
    assert assert_local_url(url, context="DB_URL", kind="postgres") == url
    assert_local_url(
        "postgresql://postgres:x@[::1]:54322/postgres", context="DB_URL", kind="postgres"
    )


def test_postgres_query_target_overrides_refused() -> None:
    base = "postgresql://postgres:x@127.0.0.1:54322/postgres"
    for q in (
        "host=remote.example",
        "hostaddr=8.8.8.8",
        "port=5432",
        "service=prod",
        "servicefile=/tmp/pg_service.conf",
        "sslmode=disable",  # outside empty allowlist
    ):
        with pytest.raises(SandboxConfigError, match="query|override|unsupported"):
            assert_local_url(f"{base}?{q}", context="DB_URL", kind="postgres")


def test_postgres_percent_encoded_and_duplicates() -> None:
    base = "postgresql://postgres:x@127.0.0.1:54322/postgres"
    with pytest.raises(SandboxConfigError, match="override|unsupported|query"):
        assert_local_url(f"{base}?%68ost=evil.example", context="DB_URL", kind="postgres")
    with pytest.raises(SandboxConfigError, match="duplicate|malformed|unsupported"):
        assert_local_url(
            f"{base}?sslmode=disable&sslmode=require", context="DB_URL", kind="postgres"
        )
    with pytest.raises(SandboxConfigError, match="malformed"):
        assert_local_url(f"{base}?%zz=1", context="DB_URL", kind="postgres")


def test_missing_workdir_refuses_invent() -> None:
    fake_inspect = [
        {
            "Config": {"Labels": {"com.supabase.cli.project": "sbfleet-test-x"}},
            "NetworkSettings": {
                "Networks": {"n": {"NetworkID": _NET_ID}},
                "Ports": {},
            },
            "Name": "/c1",
        }
    ]

    def fake_list(project_id: str) -> list[str]:
        return ["cid1"]

    with (
        patch("sbfleet.sandbox_authority.list_cli_containers", fake_list),
        patch("sbfleet.sandbox_authority.list_cli_volumes", lambda _p: []),
        patch("sbfleet.sandbox_authority._docker_json", return_value=fake_inspect),
    ):
        with pytest.raises(SandboxAuthorityError, match="workdir"):
            invent_owned_resources(
                project_id="sbfleet-test-x",
                canonical_root=Path("/tmp/app"),
                network_id=_NET_ID,
                network_name="n",
            )


def test_missing_null_ports_refuses_invent() -> None:
    def make(ports_val):  # noqa: ANN001
        return [
            {
                "Config": {
                    "Labels": {
                        "com.supabase.cli.project": "sbfleet-test-x",
                        "com.supabase.cli.workdir": "/tmp/app",
                    }
                },
                "NetworkSettings": {
                    "Networks": {"n": {"NetworkID": _NET_ID}},
                    **({"Ports": ports_val} if ports_val != "__MISSING__" else {}),
                },
                "Name": "/c1",
            }
        ]

    with (
        patch("sbfleet.sandbox_authority.list_cli_containers", lambda _p: ["cid1"]),
        patch("sbfleet.sandbox_authority.list_cli_volumes", lambda _p: []),
        patch("sbfleet.sandbox_authority._docker_json", return_value=make(None)),
    ):
        with pytest.raises(SandboxAuthorityError, match="Ports"):
            invent_owned_resources(
                project_id="sbfleet-test-x",
                canonical_root=Path("/tmp/app"),
                network_id=_NET_ID,
                network_name="n",
            )

    with (
        patch("sbfleet.sandbox_authority.list_cli_containers", lambda _p: ["cid1"]),
        patch("sbfleet.sandbox_authority.list_cli_volumes", lambda _p: []),
        patch("sbfleet.sandbox_authority._docker_json", return_value=make("__MISSING__")),
    ):
        # Rebuild without Ports key
        insp = make({})
        del insp[0]["NetworkSettings"]["Ports"]
        with patch("sbfleet.sandbox_authority._docker_json", return_value=insp):
            with pytest.raises(SandboxAuthorityError, match="Ports"):
                invent_owned_resources(
                    project_id="sbfleet-test-x",
                    canonical_root=Path("/tmp/app"),
                    network_id=_NET_ID,
                    network_name="n",
                )


def test_mixed_inventory_one_missing_ports_refuses() -> None:
    good = {
        "Config": {
            "Labels": {
                "com.supabase.cli.project": "sbfleet-test-x",
                "com.supabase.cli.workdir": "/tmp/app",
            }
        },
        "NetworkSettings": {
            "Networks": {"n": {"NetworkID": _NET_ID}},
            "Ports": {"54321/tcp": [{"HostIp": "127.0.0.1", "HostPort": "54321"}]},
        },
        "Name": "/good",
    }
    bad = {
        "Config": {
            "Labels": {
                "com.supabase.cli.project": "sbfleet-test-x",
                "com.supabase.cli.workdir": "/tmp/app",
            }
        },
        "NetworkSettings": {"Networks": {"n": {"NetworkID": _NET_ID}}},
        "Name": "/bad",
    }
    calls = {"n": 0}

    def inspect_side(argv):  # noqa: ANN001
        calls["n"] += 1
        return [good] if calls["n"] == 1 else [bad]

    with (
        patch("sbfleet.sandbox_authority.list_cli_containers", lambda _p: ["c1", "c2"]),
        patch("sbfleet.sandbox_authority.list_cli_volumes", lambda _p: []),
        patch("sbfleet.sandbox_authority._docker_json", side_effect=inspect_side),
    ):
        with pytest.raises(SandboxAuthorityError, match="Ports"):
            invent_owned_resources(
                project_id="sbfleet-test-x",
                canonical_root=Path("/tmp/app"),
                network_id=_NET_ID,
                network_name="n",
            )


def test_status_endpoints_kind_specific() -> None:
    with pytest.raises(SandboxAuthorityError, match="userinfo|HTTP"):
        status_endpoints_local(
            {
                "DB_URL": "postgresql://postgres:x@127.0.0.1:54322/postgres",
                "API_URL": "http://user:pass@127.0.0.1:54321",
            }
        )
    with pytest.raises(SandboxAuthorityError, match="query|override|unsupported"):
        status_endpoints_local(
            {
                "DB_URL": "postgresql://postgres:x@127.0.0.1:54322/postgres?host=evil",
                "API_URL": "http://127.0.0.1:54321",
            }
        )
