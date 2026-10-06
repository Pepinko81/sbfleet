"""Studio branding and public Auth URL helpers (official .env keys only)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

# Studio display defaults match upstream .env.example when unset.
DEFAULT_ORGANIZATION = "Default Organization"
DEFAULT_PROJECT = "Default Project"

_NAME_RE = re.compile(r"^[\w .,'&()+/:-]{1,100}$", re.UNICODE)


class BrandingError(ValueError):
    """Invalid branding / public Auth configuration."""


def api_external_url(public_url: str) -> str:
    """Auth external URL with exactly one trailing `/auth/v1` (upstream requirement)."""
    base = public_url.rstrip("/")
    if base.endswith("/auth/v1"):
        return base
    return f"{base}/auth/v1"


def google_callback_uri(public_url: str) -> str:
    """Google Authorized Redirect URI: `${API_EXTERNAL_URL}/callback`."""
    return f"{api_external_url(public_url)}/callback"


def validate_http_url(url: str, *, field: str, require_https: bool = False) -> str:
    text = (url or "").strip()
    if not text:
        raise BrandingError(f"{field} is required")
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"}:
        raise BrandingError(f"{field} must be http(s) URL")
    if not parsed.netloc or parsed.username or parsed.password:
        raise BrandingError(f"{field} must be a host URL without credentials")
    if require_https and parsed.scheme != "https":
        raise BrandingError(f"{field} must use https for public OAuth")
    return text.rstrip("/") if field != "additional_redirect_url" else text


def validate_display_label(name: str, *, field: str) -> str:
    text = (name or "").strip()
    if not text or len(text) > 100:
        raise BrandingError(f"{field} must be 1–100 characters")
    if any(ord(ch) < 32 for ch in text):
        raise BrandingError(f"{field} must not contain control characters")
    if not _NAME_RE.fullmatch(text):
        raise BrandingError(f"{field} contains unsupported characters")
    return text


def organization_name(meta: dict[str, Any], *, display_name: str | None = None) -> str:
    """Studio organization label. Unconfigured projects keep upstream default."""
    del display_name  # reserved for callers; do not infer Studio name from display_name
    branding = meta.get("branding") if isinstance(meta.get("branding"), dict) else {}
    raw = branding.get("organization_name") if branding else None
    if raw:
        return str(raw)
    return DEFAULT_ORGANIZATION


def project_name(meta: dict[str, Any], *, display_name: str | None = None) -> str:
    """Studio project label. Unconfigured projects keep upstream default."""
    del display_name
    branding = meta.get("branding") if isinstance(meta.get("branding"), dict) else {}
    raw = branding.get("project_name") if branding else None
    if raw:
        return str(raw)
    return DEFAULT_PROJECT


def resolve_site_url(meta: dict[str, Any], *, public_url: str) -> str:
    """Application SITE_URL. Falls back to public_url for loopback-only projects."""
    raw = meta.get("site_url")
    if raw:
        return str(raw).rstrip("/")
    return public_url.rstrip("/")


def resolve_additional_redirects(meta: dict[str, Any]) -> list[str]:
    raw = meta.get("additional_redirect_urls") or []
    if not isinstance(raw, list):
        raise BrandingError("additional_redirect_urls must be a list")
    out: list[str] = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        out.append(text)
    return out


def build_branding_meta(
    *,
    organization_name: str | None = None,
    project_name: str | None = None,
    site_url: str | None = None,
    additional_redirect_urls: list[str] | None = None,
    google_oauth_enabled: bool = False,
    public_url: str | None = None,
) -> dict[str, Any]:
    """Validate and return optional project.json fields to merge."""
    extra: dict[str, Any] = {}
    branding: dict[str, str] = {}
    if organization_name is not None:
        branding["organization_name"] = validate_display_label(
            organization_name, field="organization_name"
        )
    if project_name is not None:
        branding["project_name"] = validate_display_label(project_name, field="project_name")
    if branding:
        extra["branding"] = branding
    if site_url is not None:
        require_https = bool(public_url and public_url.startswith("https://"))
        extra["site_url"] = validate_http_url(
            site_url, field="site_url", require_https=require_https
        )
    if additional_redirect_urls is not None:
        cleaned: list[str] = []
        for u in additional_redirect_urls:
            text = str(u).strip()
            if not text:
                continue
            cleaned.append(text)
        extra["additional_redirect_urls"] = cleaned
    extra["google_oauth_enabled"] = bool(google_oauth_enabled)
    return extra


def sync_public_env_from_meta(env: dict[str, str], meta: dict[str, Any]) -> dict[str, str]:
    """Update non-secret public Auth/Studio keys from project metadata. Preserves secrets."""
    public_url = str(meta.get("public_url") or "").rstrip("/")
    if not public_url:
        raise BrandingError("public_url required to sync env")
    display = str(meta.get("display_name") or meta.get("slug") or "")
    out = dict(env)
    out["SUPABASE_PUBLIC_URL"] = public_url
    out["API_EXTERNAL_URL"] = api_external_url(public_url)
    out["SITE_URL"] = resolve_site_url(meta, public_url=public_url)
    out["ADDITIONAL_REDIRECT_URLS"] = ",".join(resolve_additional_redirects(meta))
    out["STUDIO_DEFAULT_ORGANIZATION"] = organization_name(meta, display_name=display)
    out["STUDIO_DEFAULT_PROJECT"] = project_name(meta, display_name=display)
    out["GOOGLE_ENABLED"] = "true" if meta.get("google_oauth_enabled") else "false"
    out.setdefault("GOOGLE_CLIENT_ID", env.get("GOOGLE_CLIENT_ID", ""))
    out.setdefault("GOOGLE_SECRET", env.get("GOOGLE_SECRET", ""))
    return out


def public_auth_summary(meta: dict[str, Any]) -> dict[str, str]:
    """Non-secret operator-facing Auth/Studio configuration summary."""
    public_url = str(meta.get("public_url") or "").rstrip("/")
    display = str(meta.get("display_name") or meta.get("slug") or "")
    site = resolve_site_url(meta, public_url=public_url or "http://127.0.0.1")
    redirects = resolve_additional_redirects(meta)
    return {
        "organization_name": organization_name(meta, display_name=display),
        "project_name": project_name(meta, display_name=display),
        "supabase_public_url": public_url,
        "api_external_url": api_external_url(public_url) if public_url else "",
        "site_url": site,
        "additional_redirect_urls": ",".join(redirects),
        "google_oauth_enabled": "true" if meta.get("google_oauth_enabled") else "false",
        "google_callback_uri": google_callback_uri(public_url) if public_url else "",
        "note": (
            "Studio organization/project names are display-only; "
            "Google OAuth hostname follows google_callback_uri. "
            "Set GOOGLE_CLIENT_ID/GOOGLE_SECRET in deployment/.env privately."
        ),
    }


def doctor_auth_checks(meta: dict[str, Any], env: dict[str, str] | None) -> list[dict[str, str]]:
    """Read-only Auth/branding checks for doctor. Never includes secrets."""
    checks: list[dict[str, str]] = []
    public_url = str(meta.get("public_url") or "")
    domain = meta.get("domain")

    def add(cid: str, status: str, reason: str, action: str) -> None:
        checks.append({"id": cid, "status": status, "reason": reason, "action": action})

    if not public_url:
        add("public-url", "fail", "public_url missing", "set public_url / domain at create")
        return checks

    parsed = urlparse(public_url)
    if domain and parsed.hostname and parsed.hostname != domain:
        add(
            "public-host-match",
            "fail",
            f"public_url host {parsed.hostname!r} != domain {domain!r}",
            "align domain and public_url",
        )
    else:
        add("public-host-match", "pass", parsed.hostname or public_url, "none")

    if domain and parsed.scheme != "https":
        add(
            "public-https",
            "fail",
            "public OAuth URL must be https when domain is set",
            "use https://<domain> as public_url",
        )
    elif domain:
        add("public-https", "pass", "https", "none")
    else:
        add("public-https", "pass", "loopback http allowed", "none")

    expected_api = api_external_url(public_url)
    if env is not None:
        actual_api = (env.get("API_EXTERNAL_URL") or "").rstrip("/")
        if actual_api != expected_api.rstrip("/"):
            add(
                "api-external-url",
                "fail",
                f"expected {expected_api} (exactly one /auth/v1)",
                "sync deployment/.env API_EXTERNAL_URL",
            )
        elif actual_api.count("/auth/v1") != 1:
            add(
                "api-external-url",
                "fail",
                "API_EXTERNAL_URL must contain exactly one /auth/v1",
                "fix API_EXTERNAL_URL",
            )
        else:
            add("api-external-url", "pass", actual_api, "none")

        site = env.get("SITE_URL") or ""
        if not site:
            add("site-url", "fail", "SITE_URL absent", "set SITE_URL to the application URL")
        else:
            add("site-url", "pass", site, "none")
            if domain and site.rstrip("/") == public_url.rstrip("/"):
                add(
                    "site-url-distinct",
                    "warn",
                    "SITE_URL equals Supabase public_url; app redirects usually differ",
                    "set site_url to the application origin (e.g. https://example.com)",
                )

        google_on = (env.get("GOOGLE_ENABLED") or "").lower() in {"true", "1", "yes"}
        meta_on = bool(meta.get("google_oauth_enabled"))
        if google_on or meta_on:
            if domain and parsed.scheme != "https":
                add(
                    "google-https",
                    "fail",
                    "Google OAuth enabled but public_url is not https",
                    "use https public Auth host",
                )
            cb = google_callback_uri(public_url)
            if actual_api and not cb.startswith(actual_api.rstrip("/")):
                add(
                    "google-callback",
                    "fail",
                    "callback URI inconsistent with API_EXTERNAL_URL",
                    "ensure callback is ${API_EXTERNAL_URL}/callback",
                )
            else:
                add(
                    "google-callback",
                    "pass",
                    cb,
                    "register this URI in Google Cloud Console",
                )
            if google_on and not (env.get("GOOGLE_CLIENT_ID") or "").strip():
                add(
                    "google-client-id",
                    "fail",
                    "GOOGLE_ENABLED but GOOGLE_CLIENT_ID empty",
                    "set client id in deployment/.env (never commit)",
                )
            if google_on and not (env.get("GOOGLE_SECRET") or "").strip():
                add(
                    "google-secret",
                    "fail",
                    "GOOGLE_ENABLED but GOOGLE_SECRET empty",
                    "set secret in deployment/.env (never commit)",
                )
    else:
        add("api-external-url", "warn", "deployment/.env missing", "create or restore project")

    return checks
