"""Safe argv-only subprocess runner and secret redaction."""

from __future__ import annotations

import os
import re
import signal
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# Credential-bearing URL userinfo: scheme://user:pass@host
_URL_USERINFO_RE = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^:@/\s]+):(?P<pass>[^@/\s]+)@"
)

# Minimum length for exact-value global replacement (avoids corrupting ports/booleans/usernames).
# URL userinfo redaction is always applied regardless of length.
MIN_REDACT_VALUE_LEN = 8

# Common short/trivial strings never added as exact-value secrets.
_TRIVIAL_REDACT_VALUES = frozenset(
    {
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "null",
        "none",
        "postgres",
        "postgresql",
        "mysql",
        "redis",
        "localhost",
        "127.0.0.1",
        "::1",
        "http",
        "https",
        "tcp",
        "udp",
        "user",
        "admin",
        "root",
        "anon",
        "service",
        "public",
        "private",
        "default",
        "changeme",
        "password",
        "secret",
        "token",
        "key",
    }
)


def value_eligible_for_exact_redaction(value: str | None) -> bool:
    """Return True if value is safe to globally replace without corrupting ordinary text."""
    if not value or not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) < MIN_REDACT_VALUE_LEN:
        return False
    if v.lower() in _TRIVIAL_REDACT_VALUES:
        return False
    if v.isdigit():
        return False
    return True


class ProcessError(Exception):
    """Subprocess failure that must never be treated as success."""

    def __init__(self, message: str, *, result: ProcessResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class ProcessResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    signal: int | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.signal is None


@dataclass
class Redactor:
    """Exact-value and credential-URL redaction."""

    secrets: set[str] = field(default_factory=set)

    def add(self, value: str | None) -> None:
        if value_eligible_for_exact_redaction(value):
            assert value is not None
            self.secrets.add(value)

    def add_many(self, values: Sequence[str | None]) -> None:
        for value in values:
            self.add(value)

    def redact_text(self, text: str) -> str:
        if not text:
            return text
        out = text
        # Longest first to avoid partial masking of longer secrets.
        for secret in sorted(self.secrets, key=len, reverse=True):
            if secret:
                out = out.replace(secret, "[REDACTED]")
        out = _URL_USERINFO_RE.sub(r"\g<scheme>\g<user>:[REDACTED]@", out)
        return out

    def redact(self, value: object) -> object:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, Mapping):
            return {k: self.redact(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact(v) for v in value]
        if isinstance(value, tuple):
            return tuple(self.redact(v) for v in value)
        return value


def sanitize_diagnostic(
    text: str,
    *,
    secrets: Sequence[str | None] | None = None,
    redactor: Redactor | None = None,
    max_len: int | None = None,
) -> str:
    """Redact known secrets and URL userinfo, then optionally truncate."""
    if redactor is None:
        redactor = Redactor()
        if secrets:
            redactor.add_many(secrets)
    cleaned = redactor.redact_text(text or "")
    if max_len is not None and max_len >= 0 and len(cleaned) > max_len:
        return cleaned[:max_len]
    return cleaned


# --- Configured diagnostic boundary -------------------------

CREDENTIAL_SAFE_RENDERING_UNAVAILABLE = (
    "credential-safe diagnostic rendering unavailable: "
    "supported configuration source could not be read or parsed"
)


class DiagnosticRedactorUnavailable(Exception):
    """A supported credential source exists but cannot be safely collected."""


def fleet_dotenv_paths(deployment: Path) -> list[Path]:
    """Supported project dotenv sources for ordinary diagnostic redaction."""
    return [deployment / ".env"]


def sandbox_dotenv_paths(canonical: Path) -> list[Path]:
    """Supported sandbox dotenv sources — same inventory as audit_dotenv authority."""
    locations = [
        canonical / ".env",
        canonical / ".env.local",
        canonical / "supabase" / ".env",
        canonical / "supabase" / ".env.local",
        canonical / ".supabase" / ".env",
    ]
    if canonical.parent != canonical:
        locations.extend([canonical.parent / ".env", canonical.parent / ".env.local"])
    return locations


def redactor_from_dotenv_paths(paths: Sequence[Path]) -> Redactor:
    """Build a Redactor from configured secrets in existing supported dotenv files.

    Missing paths are skipped. An existing path that cannot be read or parsed with
    the accepted dotenv grammar raises DiagnosticRedactorUnavailable — callers must
    not fall back to an empty redactor and emit raw detail.
    """
    from sbfleet.upstream import UpstreamError, parse_dotenv, secret_values_for_redaction

    redactor = Redactor()
    for path in paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            env = parse_dotenv(text)
        except (OSError, UnicodeError, ValueError, UpstreamError) as exc:
            raise DiagnosticRedactorUnavailable(
                f"supported dotenv source unreadable/unparseable: {path.name}"
            ) from exc
        redactor.add_many(secret_values_for_redaction(env))
    return redactor


def project_diagnostic_redactor(deployment: Path) -> Redactor:
    """Configured redactor for fleet/project ordinary diagnostics."""
    return redactor_from_dotenv_paths(fleet_dotenv_paths(deployment))


def sandbox_diagnostic_redactor(canonical: Path) -> Redactor:
    """Configured redactor for sandbox ordinary diagnostics."""
    return redactor_from_dotenv_paths(sandbox_dotenv_paths(canonical))


def sanitize_configured_diagnostic(
    text: str,
    *,
    redactor: Redactor | None = None,
    deployment: Path | None = None,
    sandbox_root: Path | None = None,
    max_len: int | None = None,
) -> str:
    """Ordinary diagnostic path: configured redaction before truncation.

    When a supported source exists but cannot be collected, suppress the raw
    detail and return CREDENTIAL_SAFE_RENDERING_UNAVAILABLE (never file contents).
    """
    try:
        if redactor is None:
            if sandbox_root is not None:
                redactor = sandbox_diagnostic_redactor(sandbox_root)
            elif deployment is not None:
                redactor = project_diagnostic_redactor(deployment)
            else:
                redactor = Redactor()
        return sanitize_diagnostic(text, redactor=redactor, max_len=max_len)
    except DiagnosticRedactorUnavailable:
        msg = CREDENTIAL_SAFE_RENDERING_UNAVAILABLE
        if max_len is not None and max_len >= 0 and len(msg) > max_len:
            return msg[:max_len]
        return msg


@dataclass
class StreamingRedactor:
    """Stateful rolling redaction so secrets split across chunks cannot leak.

    Holds a raw suffix long enough for the longest known secret (and a bounded
    URL-userinfo password) so incomplete matches are never emitted. Complete
    secret matches are replaced before any preceding text is released.
    """

    redactor: Redactor
    _raw: str = field(default="", init=False, repr=False)
    # Extra hold for password-bearing URL userinfo spanning chunk boundaries.
    _url_hold: int = 512

    def _hold_len(self) -> int:
        secrets_hold = max((len(s) for s in self.redactor.secrets), default=1) - 1
        return max(secrets_hold, self._url_hold)

    def _url_redact(self, text: str) -> str:
        return _URL_USERINFO_RE.sub(r"\g<scheme>\g<user>:[REDACTED]@", text)

    def feed(self, chunk: str) -> str:
        if not chunk:
            return ""
        self._raw += chunk
        parts: list[str] = []
        while self.redactor.secrets:
            best_i: int | None = None
            best_s: str | None = None
            for secret in sorted(self.redactor.secrets, key=len, reverse=True):
                idx = self._raw.find(secret)
                if idx >= 0 and (best_i is None or idx < best_i):
                    best_i = idx
                    best_s = secret
            if best_i is None or best_s is None:
                break
            parts.append(self._url_redact(self._raw[:best_i]))
            parts.append("[REDACTED]")
            self._raw = self._raw[best_i + len(best_s) :]
        hold = self._hold_len()
        if len(self._raw) > hold:
            emit = self._raw[:-hold]
            self._raw = self._raw[-hold:]
            parts.append(self._url_redact(emit))
        return "".join(parts)

    def flush(self) -> str:
        held = self._raw
        self._raw = ""
        return self.redactor.redact_text(held) if held else ""


def _signal_from_returncode(code: int) -> int | None:
    if code < 0:
        return -code
    if code >= 128:
        return code - 128
    return None


def run(
    argv: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    capture_output: bool = True,
    text: bool = True,
    input_data: str | bytes | None = None,
    inherit_stdio: bool = False,
    max_capture_bytes: int = 2_000_000,
    check: bool = False,
    new_session: bool = True,
) -> ProcessResult:
    """Run argv without shell. Child receives only the provided env (or empty)."""
    if not argv:
        raise ProcessError("argv must be non-empty")
    if any(not isinstance(a, str) for a in argv):
        raise ProcessError("argv entries must be strings")
    if inherit_stdio and capture_output:
        raise ProcessError("inherit_stdio cannot be combined with capture_output")

    child_env = dict(env) if env is not None else {}
    popen_kwargs: dict[str, object] = {
        "args": list(argv),
        "cwd": str(cwd) if cwd is not None else None,
        "env": child_env,
        "start_new_session": new_session,
    }
    if inherit_stdio:
        popen_kwargs.update(stdin=None, stdout=None, stderr=None)
    elif capture_output:
        popen_kwargs.update(
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
        )
    else:
        popen_kwargs.update(
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=text,
        )

    proc = subprocess.Popen(**popen_kwargs)  # type: ignore[arg-type]
    timed_out = False
    stdout = ""
    stderr = ""
    try:
        out, err = proc.communicate(input=input_data, timeout=timeout)
        if capture_output and not inherit_stdio:
            stdout = out or ("" if text else b"")  # type: ignore[assignment]
            stderr = err or ("" if text else b"")  # type: ignore[assignment]
            if text:
                assert isinstance(stdout, str) and isinstance(stderr, str)
                if len(stdout.encode("utf-8", errors="replace")) > max_capture_bytes:
                    stdout = (
                        stdout.encode("utf-8", errors="replace")[:max_capture_bytes].decode(
                            "utf-8", errors="replace"
                        )
                        + "\n[truncated]"
                    )
                if len(stderr.encode("utf-8", errors="replace")) > max_capture_bytes:
                    stderr = (
                        stderr.encode("utf-8", errors="replace")[:max_capture_bytes].decode(
                            "utf-8", errors="replace"
                        )
                        + "\n[truncated]"
                    )
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_group(proc)
        try:
            out, err = proc.communicate(timeout=5)
            if capture_output and not inherit_stdio:
                stdout = out or ""
                stderr = err or ""
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            _kill_group(proc)
            proc.wait(timeout=5)

    code = proc.returncode if proc.returncode is not None else -1
    sig = _signal_from_returncode(code) if not timed_out else signal.SIGTERM
    if timed_out:
        code = -signal.SIGTERM
    result = ProcessResult(
        argv=list(argv),
        returncode=code,
        stdout=stdout if isinstance(stdout, str) else "",
        stderr=stderr if isinstance(stderr, str) else "",
        timed_out=timed_out,
        signal=sig if timed_out or (code and code < 0) else _signal_from_returncode(code),
    )
    if check and not result.ok:
        raise ProcessError(
            f"command failed rc={result.returncode}: {argv[0]}",
            result=result,
        )
    return result


def _terminate_group(proc: subprocess.Popen[str] | subprocess.Popen[bytes]) -> None:
    try:
        if proc.pid:
            os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except OSError:
            pass


def _kill_group(proc: subprocess.Popen[str] | subprocess.Popen[bytes]) -> None:
    try:
        if proc.pid:
            os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
