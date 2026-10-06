"""Studio branding + public Auth URL configuration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from sbfleet.branding import (
    DEFAULT_ORGANIZATION,
    DEFAULT_PROJECT,
    BrandingError,
    api_external_url,
    build_branding_meta,
    doctor_auth_checks,
    google_callback_uri,
    organization_name,
    project_name,
    public_auth_summary,
    sync_public_env_from_meta,
)
from sbfleet.process import Redactor
from sbfleet.upstream import apply_fleet_env_defaults, secret_values_for_redaction


def test_custom_studio_names() -> None:
    meta = {
        "branding": {
            "organization_name": "Project B",
            "project_name": "Project B",
        }
    }
    assert organization_name(meta) == "Project B"
    assert project_name(meta) == "Project B"


def test_backward_compatible_studio_defaults() -> None:
    assert organization_name({}) == DEFAULT_ORGANIZATION
    assert project_name({}) == DEFAULT_PROJECT


def test_public_supabase_url_and_api_external() -> None:
    public = "https://auth.project-b.app"
    assert api_external_url(public) == "https://auth.project-b.app/auth/v1"
    # Exactly one /auth/v1 even if already present
    assert api_external_url(f"{public}/auth/v1") == "https://auth.project-b.app/auth/v1"
    assert api_external_url(f"{public}/auth/v1/") == "https://auth.project-b.app/auth/v1"


def test_site_url_and_google_callback() -> None:
    meta = {
        "public_url": "https://auth.project-b.app",
        "site_url": "https://project-b.app",
        "additional_redirect_urls": ["https://project-b.app/**"],
        "branding": {
            "organization_name": "Project B",
            "project_name": "Project B",
        },
        "google_oauth_enabled": True,
    }
    env = apply_fleet_env_defaults(
        {
            "JWT_SECRET": "a" * 32,
            "ANON_KEY": "anon",
            "SERVICE_ROLE_KEY": "service",
            "SUPABASE_PUBLISHABLE_KEY": "pub",
            "SUPABASE_SECRET_KEY": "sec",
            "JWT_KEYS": "[]",
            "JWT_JWKS": "{}",
            "POSTGRES_PASSWORD": "p" * 32,
            "DASHBOARD_PASSWORD": "d" * 32,
            "SECRET_KEY_BASE": "s" * 32,
            "VAULT_ENC_KEY": "v" * 32,
        },
        project_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        public_url=meta["public_url"],
        gateway_port=20008,
        organization_name="Project B",
        project_name="Project B",
        site_url=meta["site_url"],
        additional_redirect_urls=meta["additional_redirect_urls"],
        google_oauth_enabled=True,
    )
    assert env["SUPABASE_PUBLIC_URL"] == "https://auth.project-b.app"
    assert env["API_EXTERNAL_URL"] == "https://auth.project-b.app/auth/v1"
    assert env["API_EXTERNAL_URL"].count("/auth/v1") == 1
    assert env["SITE_URL"] == "https://project-b.app"
    assert env["ADDITIONAL_REDIRECT_URLS"] == "https://project-b.app/**"
    assert env["STUDIO_DEFAULT_ORGANIZATION"] == "Project B"
    assert env["STUDIO_DEFAULT_PROJECT"] == "Project B"
    assert env["GOOGLE_ENABLED"] == "true"
    assert google_callback_uri(meta["public_url"]) == "https://auth.project-b.app/auth/v1/callback"


def test_build_branding_meta_validates() -> None:
    extra = build_branding_meta(
        organization_name="Project B",
        project_name="Project B",
        site_url="https://project-b.app",
        additional_redirect_urls=["https://project-b.app/**"],
        google_oauth_enabled=True,
        public_url="https://auth.project-b.app",
    )
    assert extra["branding"]["organization_name"] == "Project B"
    assert extra["site_url"] == "https://project-b.app"
    assert extra["google_oauth_enabled"] is True
    with pytest.raises(BrandingError):
        build_branding_meta(site_url="http://project-b.app", public_url="https://x.app")


def test_sync_preserves_google_secret() -> None:
    meta = {
        "public_url": "https://auth.project-b.app",
        "site_url": "https://project-b.app",
        "branding": {"organization_name": "Project B", "project_name": "Project B"},
        "google_oauth_enabled": True,
        "display_name": "Project B",
    }
    env = {
        "GOOGLE_CLIENT_ID": "client-abc",
        "GOOGLE_SECRET": "super-secret-google-value",
        "API_EXTERNAL_URL": "https://old.example/auth/v1",
    }
    synced = sync_public_env_from_meta(env, meta)
    assert synced["GOOGLE_SECRET"] == "super-secret-google-value"
    assert synced["GOOGLE_CLIENT_ID"] == "client-abc"
    assert synced["API_EXTERNAL_URL"] == "https://auth.project-b.app/auth/v1"
    assert synced["STUDIO_DEFAULT_ORGANIZATION"] == "Project B"


def test_secret_redaction_includes_google() -> None:
    env = {
        "GOOGLE_SECRET": "google-secret-xyz",
        "GOOGLE_CLIENT_ID": "client-id-xyz",
        "JWT_SECRET": "j" * 32,
    }
    values = secret_values_for_redaction(env)
    assert "google-secret-xyz" in values
    # Client IDs are public identifiers — not exact-value credential redaction.
    assert "client-id-xyz" not in values
    redactor = Redactor()
    redactor.add_many(values)
    text = redactor.redact_text("id=client-id-xyz secret=google-secret-xyz")
    assert "google-secret-xyz" not in text
    assert "client-id-xyz" in text  # preserved (not a secret class value)


def test_public_auth_summary_no_secrets() -> None:
    meta = {
        "public_url": "https://auth.project-b.app",
        "site_url": "https://project-b.app",
        "branding": {"organization_name": "Project B", "project_name": "Project B"},
        "google_oauth_enabled": True,
        "display_name": "Project B",
        "slug": "project-b",
    }
    summary = public_auth_summary(meta)
    assert summary["google_callback_uri"].endswith("/auth/v1/callback")
    # Must not leak credential material — only the env key *names* in the note.
    assert "super-secret" not in " ".join(summary.values())
    assert summary["google_callback_uri"] == "https://auth.project-b.app/auth/v1/callback"
    assert "GOOGLE_CLIENT_ID=" not in summary["note"]


def test_doctor_auth_checks(tmp_path: Path) -> None:
    meta = {
        "public_url": "https://auth.project-b.app",
        "domain": "auth.project-b.app",
        "site_url": "https://project-b.app",
        "google_oauth_enabled": True,
    }
    env = {
        "API_EXTERNAL_URL": "https://auth.project-b.app/auth/v1",
        "SITE_URL": "https://project-b.app",
        "GOOGLE_ENABLED": "true",
        "GOOGLE_CLIENT_ID": "cid",
        "GOOGLE_SECRET": "sec",
        "SUPABASE_PUBLIC_URL": "https://auth.project-b.app",
    }
    checks = {c["id"]: c for c in doctor_auth_checks(meta, env)}
    assert checks["api-external-url"]["status"] == "pass"
    assert checks["public-https"]["status"] == "pass"
    assert checks["google-callback"]["status"] == "pass"

    bad = dict(env)
    bad["API_EXTERNAL_URL"] = "https://auth.project-b.app"  # missing /auth/v1
    bad_checks = {c["id"]: c for c in doctor_auth_checks(meta, bad)}
    assert bad_checks["api-external-url"]["status"] == "fail"
