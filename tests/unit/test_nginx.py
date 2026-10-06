"""Module tests."""

from __future__ import annotations

import pytest

from sbfleet.nginx import render_nginx


def test_template_without_domain() -> None:
    text = render_nginx(
        {
            "slug": "app",
            "domain": None,
            "ports": {"gateway": 20000},
        }
    )
    assert "TEMPLATE" in text


def test_domain_injection_refused() -> None:
    with pytest.raises(ValueError):
        render_nginx(
            {
                "slug": "app",
                "domain": "evil.com;rm",
                "ports": {"gateway": 20000},
            }
        )


def test_valid_domain_proxy() -> None:
    text = render_nginx(
        {
            "slug": "app",
            "domain": "app.example.com",
            "ports": {"gateway": 20000},
        }
    )
    assert "server_name app.example.com" in text
    assert "127.0.0.1:20000" in text
    assert "Upgrade" in text
    assert "X-Forwarded-Proto" in text


def test_auth_hostname_proxy() -> None:
    text = render_nginx(
        {
            "slug": "project-b",
            "domain": "auth.project-b.app",
            "ports": {"gateway": 20008},
        }
    )
    assert "server_name auth.project-b.app" in text
    assert "proxy_pass http://sbfleet_project-b" in text
    assert "127.0.0.1:20008" in text
    assert "Upgrade" in text
