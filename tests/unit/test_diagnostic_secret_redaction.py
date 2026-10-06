"""Diagnostic secret redaction."""

from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace

from sbfleet.process import (
    MIN_REDACT_VALUE_LEN,
    Redactor,
    StreamingRedactor,
    sanitize_diagnostic,
    value_eligible_for_exact_redaction,
)
from sbfleet.sandbox import _emit_child_summary, _emit_status
from sbfleet.upstream import secret_values_for_redaction

SYN_PASS = "synthetic-postgres-password-xyz"
SYN_SMTP = "synthetic-smtp-secret-value"
SYN_GH = "synthetic-gh-provider-secret"
SYN_JWT = "synthetic-jwt-secret-value-long"


def test_secret_values_include_smtp_and_provider():
    env = {
        "POSTGRES_PASSWORD": SYN_PASS,
        "SMTP_PASS": SYN_SMTP,
        "GOTRUE_EXTERNAL_GITHUB_SECRET": SYN_GH,
        "JWT_SECRET": SYN_JWT,
        "DASHBOARD_USERNAME": "admin",  # short/common — not exact-redacted
        "POSTGRES_PORT": "5432",
        "GOOGLE_CLIENT_ID": "public-client-id-value",
    }
    vals = secret_values_for_redaction(env)
    assert SYN_PASS in vals
    assert SYN_SMTP in vals
    assert SYN_GH in vals
    assert SYN_JWT in vals
    assert "admin" not in vals
    assert "5432" not in vals
    # Public client id is not a credential class value for exact redaction.
    assert "public-client-id-value" not in vals


def test_short_trivial_values_not_exact_redacted():
    assert not value_eligible_for_exact_redaction("postgres")
    assert not value_eligible_for_exact_redaction("true")
    assert not value_eligible_for_exact_redaction("5432")
    assert not value_eligible_for_exact_redaction("short")
    assert value_eligible_for_exact_redaction(SYN_PASS)
    r = Redactor()
    r.add("postgres")
    r.add(SYN_PASS)
    text = r.redact_text("user postgres connected with " + SYN_PASS)
    assert "postgres" in text  # ordinary word preserved
    assert SYN_PASS not in text
    assert "[REDACTED]" in text


def test_sanitize_before_truncate_catches_secret_near_end():
    secret = "ABCDEFGH_SYNTHETIC_SECRET_TAIL"
    # Truncating first would leave a partial secret that might not match.
    raw = ("x" * 50) + secret
    cleaned = sanitize_diagnostic(raw, secrets=[secret], max_len=60)
    assert secret not in cleaned
    assert "ABCDEFGH" not in cleaned or "[REDACTED]" in cleaned


def test_password_url_always_redacted_even_short_password():
    r = Redactor()
    out = r.redact_text("postgresql://u:ab@127.0.0.1:5432/db")
    assert "u:ab@" not in out
    assert "[REDACTED]" in out


def test_streaming_redaction_split_across_chunks():
    secret = "SYNTHETIC_SPLIT_SECRET_VALUE_99"
    r = Redactor()
    r.add(secret)
    stream = StreamingRedactor(r)
    mid = len(secret) // 2
    emitted = stream.feed("prefix-" + secret[:mid])
    emitted += stream.feed(secret[mid:] + "-suffix\n")
    emitted += stream.flush()
    assert secret not in emitted
    # No reconstructable contiguous secret across emitted stream.
    assert secret[: mid + 2] not in emitted or "[REDACTED]" in emitted
    assert "[REDACTED]" in emitted
    assert "prefix-" in emitted
    assert "-suffix" in emitted


def test_streaming_split_three_chunks_no_leak():
    secret = "AAAABBBBCCCCDDDDEEEEFFFF"
    assert len(secret) >= MIN_REDACT_VALUE_LEN
    r = Redactor()
    r.add(secret)
    stream = StreamingRedactor(r)
    parts = [secret[0:4], secret[4:12], secret[12:]]
    out = ""
    for p in parts:
        out += stream.feed(p)
    out += stream.flush()
    assert secret not in out
    assert "[REDACTED]" in out


def test_sandbox_failure_summary_redacts_secrets():
    redactor = Redactor()
    redactor.add(SYN_PASS)
    redactor.add(SYN_SMTP)
    result = SimpleNamespace(
        ok=False,
        returncode=1,
        stdout=f"started with {SYN_PASS}",
        stderr=f"smtp={SYN_SMTP} url=postgresql://u:{SYN_PASS}@127.0.0.1/db",
    )
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        _emit_child_summary(action="start", result=result, redactor=redactor)
    combined = buf.getvalue() + err.getvalue()
    assert SYN_PASS not in combined
    assert SYN_SMTP not in combined
    assert "u:" + SYN_PASS not in combined
    assert "sandbox start failed" in combined


def test_sandbox_success_does_not_forward_raw_stdout():
    redactor = Redactor()
    redactor.add(SYN_PASS)
    result = SimpleNamespace(
        ok=True,
        returncode=0,
        stdout=f"DATABASE_URL=postgresql://u:{SYN_PASS}@127.0.0.1/db\n",
        stderr="",
    )
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        _emit_child_summary(action="start", result=result, redactor=redactor)
    combined = buf.getvalue() + err.getvalue()
    assert SYN_PASS not in combined
    assert "DATABASE_URL" not in combined
    assert "sandbox start ok" in combined


def test_sandbox_status_malformed_refuses_raw_dump():
    redactor = Redactor()
    redactor.add(SYN_PASS)
    result = SimpleNamespace(
        ok=True,
        returncode=0,
        stdout=f"not-json but has {SYN_PASS}",
        stderr="",
    )
    args = SimpleNamespace(json=False)
    err = io.StringIO()
    with redirect_stdout(io.StringIO()), redirect_stderr(err):
        code = _emit_status(args, "proj", result, redactor=redactor)
    assert code != 0
    assert SYN_PASS not in err.getvalue()


def test_sandbox_status_failure_sanitized():
    redactor = Redactor()
    redactor.add(SYN_PASS)
    result = SimpleNamespace(
        ok=False,
        returncode=1,
        stdout="",
        stderr=f"boom {SYN_PASS}",
    )
    args = SimpleNamespace(json=False)
    err = io.StringIO()
    with redirect_stdout(io.StringIO()), redirect_stderr(err):
        code = _emit_status(args, "proj", result, redactor=redactor)
    assert code != 0
    assert SYN_PASS not in err.getvalue()
    assert "[REDACTED]" in err.getvalue()


def test_handler_path_uses_expanded_secret_discovery():
    """Prove discovery→sanitize path with SMTP/provider (not a pre-redacted mock)."""
    env = {
        "SMTP_PASS": SYN_SMTP,
        "GOTRUE_EXTERNAL_GITHUB_SECRET": SYN_GH,
        "POSTGRES_PASSWORD": SYN_PASS,
    }
    secrets = secret_values_for_redaction(env)
    raw = f"fail smtp={SYN_SMTP} gh={SYN_GH} db=postgresql://u:{SYN_PASS}@localhost/db"
    cleaned = sanitize_diagnostic(raw, secrets=secrets, max_len=200)
    assert SYN_SMTP not in cleaned
    assert SYN_GH not in cleaned
    assert SYN_PASS not in cleaned
