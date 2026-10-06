"""Module tests."""

from __future__ import annotations

import uuid

import pytest

from sbfleet.compose import (
    REALTIME_ALIAS,
    STANDARD_SERVICES,
    ComposeError,
    render_override,
)


def test_render_includes_all_services_and_alias() -> None:
    fid = str(uuid.uuid4())
    pid = str(uuid.uuid4())
    cp = f"sbfleet-{fid.replace('-', '')[:12]}-{pid.replace('-', '')[:12]}"
    text = render_override(
        compose_project=cp,
        fleet_id=fid,
        project_id=pid,
        gateway_port=20001,
        db_direct_port=20002,
        pooler_session_port=20003,
        pooler_transaction_port=20004,
    )
    for svc in STANDARD_SERVICES:
        assert f"{cp}-{svc}" in text
        assert f"  {svc}:" in text
    assert "ports: !override" in text
    assert "127.0.0.1:20001:8000/tcp" in text
    assert "127.0.0.1:20002:5432/tcp" in text
    assert "127.0.0.1:20003:5432/tcp" in text
    assert "127.0.0.1:20004:6543/tcp" in text
    assert REALTIME_ALIAS in text
    assert "API_JWT_JWKS" in text
    assert "GOTRUE_JWT_KEYS" in text
    assert "GOTRUE_EXTERNAL_GOOGLE_ENABLED" in text
    assert "GOTRUE_EXTERNAL_GOOGLE_REDIRECT_URI" in text
    assert "${API_EXTERNAL_URL}/callback" in text
    assert "io.sbfleet.fleet" in text


def test_invalid_compose_project_rejected() -> None:
    with pytest.raises(ComposeError):
        render_override(
            compose_project="supabase",
            fleet_id=str(uuid.uuid4()),
            project_id=str(uuid.uuid4()),
            gateway_port=1,
            db_direct_port=2,
            pooler_session_port=3,
            pooler_transaction_port=4,
        )
