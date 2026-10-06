"""Pinned official upstream snapshot cache and materialization."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from pathlib import Path

from sbfleet.process import run

OFFICIAL_REPO = "https://github.com/supabase/supabase.git"
PINNED_REF = "self-hosted/v0.8.2"
PINNED_SHA = "564eab8ad7840b13324f68b1bfac074ef8d51c21"
# Reviewed official SHAs for V1 update transitions (peeled commit objects).
KNOWN_REF_SHAS: dict[str, str] = {
    "self-hosted/v0.8.1": "8c7a4d9dbbaf8b552893822e89d7bf06f33f9220",
    "self-hosted/v0.8.2": PINNED_SHA,
}
# Directed reviewed update edges only. Semver ordering is never authority.
REVIEWED_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("self-hosted/v0.8.1", "self-hosted/v0.8.2"),
    }
)
NUMERIC_TAG_RE = re.compile(r"^self-hosted/v\d+\.\d+\.\d+$")
SPARSE_PATHS = ("docker",)

# Source-pin update.sh contract (self-hosted/v0.8.1 @ 8c7a4d9…), sha256 recorded at review.
UPDATE_SH_SOURCE_SHA256 = "a0c8f1630af9a076a8fd723444de88eda5a91b3284199acb500d0da72cb7fdd6"
# Contract summary (adapter must match; do not invent flags):
#   argv: --to <tag>, --from <ref>, --dry-run, --yes|-y, -h|--help
#   exits: 0 clean/dry-run; 1 die; 2 apply-with-conflicts (stamp not advanced)
#   dry-run: exits 0 even when conflicts would be reported
#   .dist: differing target update.sh staged as update.sh.dist (never overwrites $0)
#   backup: backups/pre-update-*.tgz in cwd (plaintext; may include .env)
#   tools: sh, git, tar, cmp, date; env SUPABASE_REPO_URL (default official github)


class UpstreamError(Exception):
    """Upstream materialization failure (fail closed)."""


def validate_ref(ref: str) -> str:
    if not NUMERIC_TAG_RE.fullmatch(ref):
        raise UpstreamError(
            f"ref {ref!r} rejected: only stable numeric self-hosted/vX.Y.Z tags allowed"
        )
    if ref in {"master", "main", "latest"} or ref.endswith("/latest"):
        raise UpstreamError(f"ref {ref!r} forbidden")
    return ref


def validate_sha(sha: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise UpstreamError(f"sha must be 40 lowercase hex chars, got {sha!r}")
    return sha


def resolve_ref_sha(ref: str) -> str:
    """Resolve a stable numeric tag to a reviewed peeled commit SHA."""
    validate_ref(ref)
    sha = KNOWN_REF_SHAS.get(ref)
    if sha is None:
        raise UpstreamError(f"ref {ref!r} has no reviewed SHA in V1; record compatibility first")
    return validate_sha(sha)


def bare_semver(ref: str) -> str:
    validate_ref(ref)
    return ref.split("/v", 1)[1]


def cache_dir(root: Path, sha: str = PINNED_SHA) -> Path:
    validate_sha(sha)
    return Path(root) / "cache" / "upstream" / sha


def stamp_contents(*, ref: str, sha: str) -> str:
    return f"ref={ref}\nsha={sha}\n"


def write_version_stamp(deployment: Path, *, ref: str = PINNED_REF, sha: str = PINNED_SHA) -> Path:
    path = Path(deployment) / ".supabase-version"
    path.write_text(f"ref={ref}\n", encoding="utf-8")
    os.chmod(path, 0o600)
    meta = Path(deployment) / ".sbfleet-upstream"
    meta.write_text(stamp_contents(ref=ref, sha=sha), encoding="utf-8")
    os.chmod(meta, 0o600)
    return path


def _sanitized_git_env() -> dict[str, str]:
    # Minimal env: no credential helpers from user config, no GIT_* overrides.
    path = os.environ.get("PATH", "/usr/bin:/bin")
    return {
        "PATH": path,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GCM_INTERACTIVE": "never",
        "LC_ALL": "C",
        "HOME": tempfile.gettempdir(),
        # Disable any credential helper for public clone.
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "",
        "GIT_CONFIG_KEY_1": "http.version",
        "GIT_CONFIG_VALUE_1": "HTTP/1.1",
    }


def _git(argv: list[str], *, cwd: Path | None = None, timeout: float = 120.0) -> None:
    result = run(
        ["git", *argv],
        cwd=cwd,
        env=_sanitized_git_env(),
        timeout=timeout,
        check=False,
    )
    if not result.ok:
        detail = (result.stderr or result.stdout or "").strip()
        raise UpstreamError(f"git {' '.join(argv[:3])} failed: {detail[:500]}")


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# Critical vendor paths relative to docker/ — digests anchored at pinned commit fetch.
CRITICAL_VENDOR_FILES: tuple[str, ...] = (
    "docker-compose.yml",
    "run.sh",
    "utils/generate-keys.sh",
    "utils/add-new-auth-keys.sh",
)


def critical_vendor_digests(docker_dir: Path) -> dict[str, str]:
    digests: dict[str, str] = {}
    for rel in CRITICAL_VENDOR_FILES:
        path = Path(docker_dir) / rel
        if not path.is_file():
            raise UpstreamError(f"critical vendor file missing at pin: {rel}")
        digests[rel] = _file_sha256(path)
    return digests


_SAFE_CRITICAL_REL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_DIGEST_HEX64 = re.compile(r"^[0-9a-f]{64}$")
CACHE_MARKER_FORMAT_VERSION = 1


def _safe_critical_relpath(rel: str) -> str:
    """Refuse absolute, empty, parent, or otherwise unsafe critical digest paths."""
    if not isinstance(rel, str) or not rel:
        raise UpstreamError("critical digest path must be a non-empty string")
    if rel.startswith("/") or rel.startswith("\\"):
        raise UpstreamError(f"critical digest path must be relative: {rel!r}")
    if "\\" in rel:
        raise UpstreamError(f"critical digest path uses unsupported separators: {rel!r}")
    parts = rel.split("/")
    if any(p in {"", ".", ".."} for p in parts):
        raise UpstreamError(f"critical digest path is unsafe: {rel!r}")
    if not _SAFE_CRITICAL_REL.fullmatch(rel):
        raise UpstreamError(f"critical digest path rejected: {rel!r}")
    return rel


def validate_critical_digests_manifest(
    meta: dict,
    *,
    expected_sha: str,
    expected_ref: str | None = None,
) -> dict[str, str]:
    """Fail closed on incomplete/malformed critical-cache integrity markers.

    This validates cache trustworthiness. It does not prove a complete
    updater-owned target surface.
    """
    validate_sha(expected_sha)
    if not isinstance(meta, dict):
        raise UpstreamError("cache marker must be an object")
    fmt = meta.get("format_version")
    if fmt != CACHE_MARKER_FORMAT_VERSION:
        raise UpstreamError(
            f"cache marker format_version unsupported: {fmt!r} "
            f"(require {CACHE_MARKER_FORMAT_VERSION})"
        )
    sha = meta.get("sha")
    if sha != expected_sha:
        raise UpstreamError(f"cache sha mismatch: {sha} != {expected_sha}")
    ref = meta.get("ref")
    if not isinstance(ref, str) or not ref.strip():
        raise UpstreamError(
            "cache marker missing nonempty reviewed ref "
            "(incomplete historical markers must rematerialize via exact-pin path)"
        )
    validate_ref(ref)
    if expected_ref is not None:
        validate_ref(expected_ref)
        if ref != expected_ref:
            raise UpstreamError(f"cache ref mismatch: {ref!r} != {expected_ref!r}")
    known = KNOWN_REF_SHAS.get(ref)
    if known is None:
        raise UpstreamError(f"cache ref {ref!r} has no reviewed SHA")
    if known != expected_sha:
        raise UpstreamError(f"cache marker ref {ref!r} does not match approved SHA for that pin")
    digests = meta.get("critical_digests")
    if not isinstance(digests, dict) or not digests:
        raise UpstreamError(
            "cache marker missing critical_digests (upstream-anchored pin integrity)"
        )
    required = set(CRITICAL_VENDOR_FILES)
    got_keys = set(digests.keys())
    missing = sorted(required - got_keys)
    extra = sorted(got_keys - required)
    if missing:
        raise UpstreamError(
            "cache marker incomplete critical_digests; missing: " + ", ".join(missing)
        )
    if extra:
        raise UpstreamError(
            "cache marker has unexpected critical_digests paths: " + ", ".join(extra)
        )
    out: dict[str, str] = {}
    for rel in CRITICAL_VENDOR_FILES:
        _safe_critical_relpath(rel)
        digest = digests[rel]
        if not isinstance(digest, str) or not _DIGEST_HEX64.fullmatch(digest):
            raise UpstreamError(f"malformed critical digest for {rel}")
        out[rel] = digest
    return out


def verify_deployment_vendor(deployment: Path, *, sha: str, root: Path | None = None) -> None:
    """Verify deployment vendor bytes against upstream-anchored cache digests."""
    cache = cache_dir(root, sha) if root is not None else None
    if cache is None or not cache.exists():
        raise UpstreamError("upstream cache unavailable for vendor verification")
    verify_cache(cache, sha=sha)
    import json

    meta = json.loads((cache / ".sbfleet-cache.json").read_text(encoding="utf-8"))
    expected = validate_critical_digests_manifest(meta, expected_sha=sha)
    for rel, digest in expected.items():
        path = Path(deployment) / rel
        if not path.is_file():
            raise UpstreamError(f"deployment missing critical vendor file: {rel}")
        actual = _file_sha256(path)
        if actual != digest:
            raise UpstreamError(f"deployment vendor drift for {rel}: {actual[:12]}!={digest[:12]}")


def verify_stamp_matches_meta(deployment: Path, meta: dict) -> None:
    stamp = Path(deployment) / ".supabase-version"
    if not stamp.is_file():
        raise UpstreamError("deployment .supabase-version missing")
    text = stamp.read_text(encoding="utf-8").strip()
    upstream = meta.get("upstream") or {}
    ref = str(upstream.get("ref") or "")
    sha = str(upstream.get("sha") or "")
    if ref and f"ref={ref}" not in text and text != ref:
        raise UpstreamError(f"stamp/metadata ref mismatch: stamp={text!r} expected ref={ref!r}")
    fleet_stamp = Path(deployment) / ".sbfleet-upstream"
    if fleet_stamp.is_file():
        body = fleet_stamp.read_text(encoding="utf-8")
        if sha and sha not in body:
            raise UpstreamError(f"sbfleet-upstream sha mismatch vs metadata sha={sha[:12]}")


def verify_cache(cache: Path, *, sha: str = PINNED_SHA) -> None:
    cache = Path(cache)
    if not cache.is_dir() or cache.is_symlink():
        raise UpstreamError(f"cache missing or symlink: {cache}")
    marker = cache / ".sbfleet-cache.json"
    docker = cache / "docker"
    if not docker.is_dir() or docker.is_symlink():
        raise UpstreamError(f"cache docker/ missing: {cache}")
    compose = docker / "docker-compose.yml"
    if not compose.is_file() or compose.is_symlink():
        raise UpstreamError("cache missing docker-compose.yml")
    if not marker.is_file():
        raise UpstreamError("cache marker missing")
    import json

    meta = json.loads(marker.read_text(encoding="utf-8"))
    # Spot-check: compose must be non-empty and not world-writable.
    st = compose.stat()
    if st.st_size < 100:
        raise UpstreamError("cache compose suspiciously small")
    if st.st_mode & 0o002:
        raise UpstreamError("cache world-writable")
    # Exact critical-cache integrity: nonempty subset is not enough.
    expected = validate_critical_digests_manifest(meta, expected_sha=sha)
    for rel, digest in expected.items():
        # Paths in marker are relative to docker/ (cache root candidates for safety).
        candidates = [docker / rel, cache / rel]
        found = next((p for p in candidates if p.is_file()), None)
        if found is None:
            raise UpstreamError(f"critical vendor file missing: {rel}")
        actual = _file_sha256(found)
        if actual != digest:
            raise UpstreamError(
                f"vendor drift vs pinned upstream for {rel}: {actual[:12]}!={digest[:12]}"
            )


def materialize_cache(
    root: Path,
    *,
    ref: str = PINNED_REF,
    sha: str = PINNED_SHA,
    repo_url: str = OFFICIAL_REPO,
    force: bool = False,
) -> Path:
    """Fetch official docker/ into immutable cache/<sha>/."""
    from sbfleet import registry as reg

    validate_ref(ref)
    validate_sha(sha)
    if repo_url != OFFICIAL_REPO:
        raise UpstreamError("arbitrary repository overrides are forbidden")
    dest = cache_dir(root, sha)
    cache_parent = dest.parent
    if dest.exists() and not force:
        try:
            verify_cache(dest, sha=sha)
            return dest
        except UpstreamError:
            # Corrupt cache: replace through the shared checked deletion boundary.
            try:
                reg.safe_rmtree(dest, under=cache_parent)
            except reg.OwnershipError as exc:
                raise UpstreamError(
                    f"refusing to replace corrupt cache without mount authority: {exc}"
                ) from exc

    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="sbfleet-upstream-", dir=str(dest.parent)))
    try:
        _git(["init", "--quiet", str(staging)])
        _git(["-C", str(staging), "remote", "add", "origin", repo_url])
        # Shallow fetch of the exact commit; verify SHA before sparse checkout.
        _git(
            [
                "-C",
                str(staging),
                "fetch",
                "--quiet",
                "--depth=1",
                "--filter=blob:none",
                "origin",
                sha,
            ],
            timeout=300.0,
        )
        _git(["-C", str(staging), "checkout", "--quiet", sha])
        head = run(
            ["git", "-C", str(staging), "rev-parse", "HEAD"],
            env=_sanitized_git_env(),
            check=True,
        )
        got = head.stdout.strip()
        if got != sha:
            raise UpstreamError(f"resolved HEAD {got} does not match pinned sha {sha}")
        # Sparse: keep only docker/
        docker_src = staging / "docker"
        if not docker_src.is_dir():
            raise UpstreamError("fetched tree missing docker/")
        # Also copy root LICENSE if present for attribution.
        final = Path(tempfile.mkdtemp(prefix="sbfleet-cache-", dir=str(dest.parent)))
        try:
            shutil.copytree(docker_src, final / "docker", symlinks=False)
            for name in ("LICENSE", "LICENSE.md", "COPYING"):
                lic = staging / name
                if lic.is_file():
                    shutil.copy2(lic, final / name)
            import json

            marker = {
                "format_version": 1,
                "ref": ref,
                "sha": sha,
                "repo": OFFICIAL_REPO,
                "critical_digests": critical_vendor_digests(final / "docker"),
            }
            (final / ".sbfleet-cache.json").write_text(
                json.dumps(marker, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.chmod(final / ".sbfleet-cache.json", 0o600)
            verify_cache(final, sha=sha)
            if dest.exists():
                try:
                    reg.safe_rmtree(dest, under=cache_parent)
                except reg.OwnershipError as exc:
                    raise UpstreamError(
                        f"refusing to replace existing cache without mount authority: {exc}"
                    ) from exc
            os.rename(final, dest)
        except Exception:
            if final.exists():
                try:
                    reg.safe_rmtree(final, under=cache_parent)
                except reg.OwnershipError:
                    # Prefer leaving invalid staging for diagnosis over weaker delete.
                    pass
            raise
    finally:
        if staging.exists():
            try:
                reg.safe_rmtree(staging, under=cache_parent)
            except reg.OwnershipError:
                # Terminal refusal — do not fall back to unguarded rmtree.
                pass
    # Make cache tree read-only for owner writes on marker only; contents not shared writable.
    return dest


def copy_vendor_docker(
    cache: Path,
    deployment: Path,
    *,
    sha: str = PINNED_SHA,
    ref: str = PINNED_REF,
) -> None:
    """Copy docker/ into deployment/ with preserved bytes; no shared writable files."""
    verify_cache(cache, sha=sha)
    deployment = Path(deployment)
    if deployment.exists():
        if any(deployment.iterdir()):
            raise UpstreamError(f"deployment directory not empty: {deployment}")
    else:
        deployment.mkdir(parents=True, mode=0o700)
    os.chmod(deployment, 0o700)
    src = cache / "docker"
    # Copy file-by-file to avoid hardlink sharing.
    for root, dirs, files in os.walk(src):
        rel = Path(root).relative_to(src)
        # Reject path escape / absolute / symlink components.
        for part in Path(root).parts:
            if part in {".", ".."}:
                continue
        for d in list(dirs):
            if d.startswith(".") and d not in {
                ".",
            }:
                pass
            src_d = Path(root) / d
            if src_d.is_symlink():
                raise UpstreamError(f"refusing symlink in vendor tree: {src_d}")
        dest_dir = deployment / rel
        dest_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(dest_dir, 0o700)
        for name in files:
            s = Path(root) / name
            if s.is_symlink():
                raise UpstreamError(f"refusing symlink file: {s}")
            # Block path tricks
            if ".." in name or name.startswith("/"):
                raise UpstreamError(f"malicious path: {name}")
            d = dest_dir / name
            shutil.copy2(s, d)
            mode = 0o600 if name in {".env", ".env.example"} or name.endswith(".key") else 0o644
            if name.endswith(".sh"):
                mode = 0o700
            os.chmod(d, mode)
    write_version_stamp(deployment, ref=ref, sha=sha)
    # Attribution
    for name in ("LICENSE", "LICENSE.md"):
        lic = cache / name
        if lic.is_file():
            shutil.copy2(lic, deployment / name)


def vendor_file_digest(deployment: Path, relative: str) -> str:
    path = Path(deployment) / relative
    if path.is_symlink() or not path.is_file():
        raise UpstreamError(f"missing vendor file: {relative}")
    return _file_sha256(path)


# --- Secret generation ---

REQUIRED_ENV_KEYS = frozenset(
    {
        "JWT_SECRET",
        "ANON_KEY",
        "SERVICE_ROLE_KEY",
        "SUPABASE_PUBLISHABLE_KEY",
        "SUPABASE_SECRET_KEY",
        "JWT_KEYS",
        "JWT_JWKS",
        "POSTGRES_PASSWORD",
        "DASHBOARD_USERNAME",
        "DASHBOARD_PASSWORD",
        "SECRET_KEY_BASE",
        "VAULT_ENC_KEY",
        "POOLER_TENANT_ID",
    }
)


def require_local_node() -> str:
    """Require local Node >=16; never fall back to Docker node images."""
    path = shutil.which("node")
    if not path:
        raise UpstreamError(
            "Node.js >=16 is required for secret generation (Docker fallback refused)"
        )
    result = run([path, "-v"], env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, check=False)
    ver = (result.stdout or result.stderr or "").strip()
    if not result.ok:
        raise UpstreamError("unable to execute node")
    major_s = ver.lstrip("v").split(".", 1)[0]
    try:
        major = int(major_s)
    except ValueError as exc:
        raise UpstreamError(f"unrecognized node version: {ver}") from exc
    if major < 16:
        raise UpstreamError(f"Node.js >=16 required, found {ver} (Docker fallback refused)")
    if not shutil.which("openssl"):
        raise UpstreamError("OpenSSL is required for secret generation")
    return path


def _refuse_unsupported_interpolation(value: str, *, lineno: int) -> None:
    """Refuse Compose-expandable dollar forms; allow ``$$`` literal escapes only.

    Unquoted and double-quoted dotenv values must mean the same thing to sbfleet
    and Docker Compose. V1 rejects interpolation rather than implementing it.
    """
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch != "$":
            i += 1
            continue
        if i + 1 < n and value[i + 1] == "$":
            i += 2
            continue
        if i + 1 < n and value[i + 1] == "{":
            raise UpstreamError(
                f"unsupported interpolation on line {lineno} (literal $$ only; refuse $NAME/${{…}})"
            )
        # Compose expands $NAME where NAME is [_A-Za-z][_A-Za-z0-9]*
        if i + 1 < n and re.match(r"[_A-Za-z]", value[i + 1]):
            raise UpstreamError(
                f"unsupported interpolation on line {lineno} (literal $$ only; refuse $NAME/${{…}})"
            )
        i += 1


def _refuse_controls(value: str, *, what: str) -> None:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise UpstreamError(f"control character in dotenv value for {what}")


def parse_dotenv(text: str) -> dict[str, str]:
    """Strict supported dotenv subset — never source/eval; refuse unsupported syntax."""
    result: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise UpstreamError(f"malformed dotenv line {lineno}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise UpstreamError(f"invalid dotenv key on line {lineno}")
        if key in result:
            raise UpstreamError(f"duplicate dotenv key: {key}")
        _refuse_controls(value, what=f"line {lineno}")
        if value[:1] in {'"', "'"}:
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise UpstreamError(f"unmatched quote on dotenv line {lineno}")
            inner = value[1:-1]
            if quote == "'":
                if "'" in inner:
                    raise UpstreamError(f"unsupported single-quote content on line {lineno}")
                # Single-quoted: Compose does not interpolate; keep opaque literal.
                value = inner
            else:
                out: list[str] = []
                i = 0
                while i < len(inner):
                    ch = inner[i]
                    if ch == "\\":
                        if i + 1 >= len(inner):
                            raise UpstreamError(f"trailing backslash on line {lineno}")
                        nxt = inner[i + 1]
                        if nxt == "\\":
                            out.append("\\")
                        elif nxt == '"':
                            out.append('"')
                        elif nxt == "n":
                            out.append("\n")
                        else:
                            raise UpstreamError(
                                f"unsupported escape \\{nxt} on dotenv line {lineno}"
                            )
                        i += 2
                        continue
                    if ch == '"':
                        raise UpstreamError(f"unescaped quote on dotenv line {lineno}")
                    out.append(ch)
                    i += 1
                # Refuse Compose-expandable forms on the pre-unwrap string.
                _refuse_unsupported_interpolation("".join(out), lineno=lineno)
                value = "".join(out)
                # Compose dotenv: `$$` is a literal `$`.
                value = value.replace("$$", "$")
        else:
            # Unquoted: refuse forms whose Compose meaning differs from a literal read.
            # Leading whitespace after '=' is stripped by Compose — refuse, do not
            # silently reinterpret operator files.
            if value[:1] in {" ", "\t"}:
                raise UpstreamError(
                    f"unsupported unquoted whitespace after '=' on dotenv line {lineno} "
                    "(quote the value or remove surrounding spaces)"
                )
            if " #" in value:
                value = value.split(" #", 1)[0].rstrip()
                if value[:1] in {" ", "\t"}:
                    raise UpstreamError(
                        f"unsupported unquoted whitespace after '=' on dotenv line {lineno} "
                        "(quote the value or remove surrounding spaces)"
                    )
            # Unquoted $$ would be a literal `$` under Compose but remained `$$` here.
            if "$$" in value:
                raise UpstreamError(
                    f"unsupported unquoted $$ on dotenv line {lineno} "
                    "(use double quotes so $$ means a literal $, or write a single $)"
                )
            _refuse_unsupported_interpolation(value, lineno=lineno)
        if "\n" in value or "\r" in value:
            raise UpstreamError(f"newline in dotenv value for {key}")
        _refuse_controls(value, what=key)
        result[key] = value
    return result


def dump_dotenv(values: dict[str, str]) -> str:
    """Serialize dotenv for Compose: escape `$` as `$$` inside double quotes."""
    lines = []
    for key in sorted(values):
        val = values[key]
        _refuse_controls(val, what=key)
        if any(ch in val for ch in " \t#\"'\\$={}"):
            escaped = val.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$")
            lines.append(f'{key}="{escaped}"')
        else:
            lines.append(f"{key}={val}")
    return "\n".join(lines) + "\n"


def atomic_write_dotenv(path: Path, values: dict[str, str]) -> None:
    """Atomically rewrite dotenv preserving existing mode bits (same-directory replace).

    Caller must have already validated the path (e.g. assert_secret_file). Does not
    widen permissions; does not chown. On failure the original file is left intact.
    """
    path = Path(path)
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise UpstreamError(f".env missing for atomic write: {path}") from exc
    mode = st.st_mode & 0o777
    text = dump_dotenv(values)
    encoded = text.encode("utf-8")
    parent = path.parent
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-env-", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        dir_fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def validate_generated_env(env: dict[str, str]) -> None:
    missing = sorted(REQUIRED_ENV_KEYS - set(env))
    if missing:
        raise UpstreamError(f"generated .env missing keys: {', '.join(missing)}")
    if env.get("ANON_KEY") == env.get("SERVICE_ROLE_KEY"):
        raise UpstreamError("ANON_KEY and SERVICE_ROLE_KEY must differ")
    if env.get("SUPABASE_PUBLISHABLE_KEY") == env.get("SUPABASE_SECRET_KEY"):
        raise UpstreamError("publishable and secret API keys must differ")
    for key in ("JWT_KEYS", "JWT_JWKS"):
        try:
            import json

            parsed = json.loads(env[key])
        except json.JSONDecodeError as exc:
            raise UpstreamError(f"{key} is not valid JSON") from exc
        if key == "JWT_JWKS":
            if not isinstance(parsed, dict) or "keys" not in parsed:
                raise UpstreamError(f"{key} missing keys array")
        elif not isinstance(parsed, list) or not parsed:
            raise UpstreamError(f"{key} must be a non-empty JSON array")
    for key in ("JWT_SECRET", "POSTGRES_PASSWORD", "DASHBOARD_PASSWORD"):
        if len(env.get(key, "")) < 16:
            raise UpstreamError(f"{key} too short")


def apply_fleet_env_defaults(
    env: dict[str, str],
    *,
    project_id: str,
    public_url: str,
    gateway_port: int,
    organization_name: str | None = None,
    project_name: str | None = None,
    site_url: str | None = None,
    additional_redirect_urls: list[str] | None = None,
    google_oauth_enabled: bool = False,
) -> dict[str, str]:
    """Unique dashboard/tenant/URLs, Studio branding, and safe signup defaults."""
    from sbfleet.branding import (
        DEFAULT_ORGANIZATION,
        DEFAULT_PROJECT,
        api_external_url,
    )

    out = dict(env)
    compact = project_id.replace("-", "")
    project12 = compact[:12]
    base = public_url.rstrip("/")
    out["DASHBOARD_USERNAME"] = f"sb_{project12}"
    out["POOLER_TENANT_ID"] = compact
    out["SUPABASE_PUBLIC_URL"] = base
    # Official self-hosted expects API_EXTERNAL_URL to include /auth/v1 exactly once.
    out["API_EXTERNAL_URL"] = api_external_url(base)
    out["SITE_URL"] = (site_url or base).rstrip("/")
    redirects = additional_redirect_urls or []
    out["ADDITIONAL_REDIRECT_URLS"] = ",".join(redirects)
    out["STUDIO_DEFAULT_ORGANIZATION"] = organization_name or DEFAULT_ORGANIZATION
    out["STUDIO_DEFAULT_PROJECT"] = project_name or DEFAULT_PROJECT
    out["API_GW_HTTP_PORT"] = str(gateway_port)
    out["KONG_HTTP_PORT"] = str(gateway_port)
    out["POSTGRES_PORT"] = "5432"
    out["OPENAI_API_KEY"] = ""
    out["ENABLE_EMAIL_SIGNUP"] = "false"
    out["ENABLE_EMAIL_AUTOCONFIRM"] = "false"
    out["ENABLE_PHONE_SIGNUP"] = "false"
    out["ENABLE_PHONE_AUTOCONFIRM"] = "false"
    out["GOOGLE_ENABLED"] = "true" if google_oauth_enabled else "false"
    out.setdefault("GOOGLE_CLIENT_ID", "")
    out.setdefault("GOOGLE_SECRET", "")
    out["COMPOSE_FILE"] = "docker-compose.yml:docker-compose.override.yml"
    out["COMPOSE_PATH_SEPARATOR"] = ":"
    return out


def _scrub_old_files(directory: Path) -> None:
    for path in directory.rglob("*.old"):
        try:
            path.unlink()
        except OSError:
            pass


def generate_secrets_in_scratch(
    vendor_docker: Path,
    scratch: Path,
    *,
    project_id: str,
    public_url: str,
    gateway_port: int,
    organization_name: str | None = None,
    project_name: str | None = None,
    site_url: str | None = None,
    additional_redirect_urls: list[str] | None = None,
    google_oauth_enabled: bool = False,
) -> dict[str, str]:
    """
    Run official key scripts in a private 0700 scratch directory.
    Captures all output (never echoed), validates, returns env mapping.
    """
    require_local_node()
    scratch = Path(scratch)
    if scratch.exists():
        raise UpstreamError(f"scratch already exists: {scratch}")
    scratch.mkdir(mode=0o700, parents=True)
    os.chmod(scratch, 0o700)
    # Copy only what generators need: .env.example, utils/, and compose for their edits.
    example = vendor_docker / ".env.example"
    if not example.is_file():
        raise UpstreamError("vendor .env.example missing")
    shutil.copy2(example, scratch / ".env.example")
    shutil.copy2(example, scratch / ".env")
    os.chmod(scratch / ".env", 0o600)
    utils_src = vendor_docker / "utils"
    shutil.copytree(utils_src, scratch / "utils", symlinks=False)
    # Generators may touch compose; provide a disposable copy so vendor stays pristine.
    for name in ("docker-compose.yml",):
        src = vendor_docker / name
        if src.is_file():
            shutil.copy2(src, scratch / name)

    gen_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(scratch / ".home"),
        "LC_ALL": "C",
    }
    (scratch / ".home").mkdir(mode=0o700)

    # Force PATH node; scripts check `command -v node` — ensure our node is first.
    scripts = [
        ["sh", "utils/generate-keys.sh", "--update-env"],
        ["sh", "utils/add-new-auth-keys.sh", "--update-env"],
    ]
    captures: list[str] = []
    try:
        for argv in scripts:
            result = run(argv, cwd=scratch, env=gen_env, timeout=120.0, check=False)
            captures.append(result.stdout + "\n" + result.stderr)
            if not result.ok:
                raise UpstreamError(f"secret generator failed: {argv[1]}")
        env_path = scratch / ".env"
        if not env_path.is_file():
            raise UpstreamError("generator did not produce .env")
        env = parse_dotenv(env_path.read_text(encoding="utf-8"))
        env = apply_fleet_env_defaults(
            env,
            project_id=project_id,
            public_url=public_url,
            gateway_port=gateway_port,
            organization_name=organization_name,
            project_name=project_name,
            site_url=site_url,
            additional_redirect_urls=additional_redirect_urls,
            google_oauth_enabled=google_oauth_enabled,
        )
        validate_generated_env(env)
        # Rewrite .env with fleet defaults applied.
        env_path.write_text(dump_dotenv(env), encoding="utf-8")
        os.chmod(env_path, 0o600)
        _scrub_old_files(scratch)
        return env
    finally:
        # Discard plaintext captures from memory callers; wipe scratch .old always.
        _scrub_old_files(scratch)
        del captures


def install_env_only(scratch_env: Path, deployment: Path) -> Path:
    """Copy only validated .env into deployment; leave vendor compose untouched."""
    deployment = Path(deployment)
    dest = deployment / ".env"
    if dest.exists():
        raise UpstreamError(".env already exists — refuse regenerate on resume path")
    text = scratch_env.read_text(encoding="utf-8")
    env = parse_dotenv(text)
    validate_generated_env(env)
    dest.write_text(dump_dotenv(env), encoding="utf-8")
    os.chmod(dest, 0o600)
    return dest


# Explicit credential-key classes for diagnostic redaction.
# Values are collected for exact-value redaction; short/trivial values are filtered
# by process.value_eligible_for_exact_redaction (URL userinfo is always masked).
CREDENTIAL_KEY_EXACT: frozenset[str] = frozenset(
    {
        # JWT / service / admin
        "JWT_SECRET",
        "ANON_KEY",
        "SERVICE_ROLE_KEY",
        "SUPABASE_PUBLISHABLE_KEY",
        "SUPABASE_SECRET_KEY",
        "SECRET_KEY_BASE",
        "VAULT_ENC_KEY",
        "JWT_KEYS",
        "JWT_JWKS",
        "ANON_KEY_ASYMMETRIC",
        "SERVICE_ROLE_KEY_ASYMMETRIC",
        # Database passwords
        "POSTGRES_PASSWORD",
        "SUPABASE_DB_PASSWORD",
        # Dashboard
        "DASHBOARD_PASSWORD",
        # SMTP
        "SMTP_PASS",
        "SMTP_PASSWORD",
        "SMTP_USER",
        "SMTP_USERNAME",
        # Google / legacy provider
        "GOOGLE_SECRET",
        "GOOGLE_CLIENT_SECRET",
    }
)

# Key-name patterns for additional configured provider/OAuth/SMTP secrets.
_CREDENTIAL_KEY_SUFFIXES: tuple[str, ...] = (
    "_PASSWORD",
    "_SECRET",
    "_TOKEN",
    "_API_KEY",
    "_PRIVATE_KEY",
    "_CLIENT_SECRET",
    "_SERVICE_KEY",
    "_SERVICE_ROLE_KEY",
)

# Keys that look secretish but are public identifiers — never exactly redact their values
# solely from the key name (usernames/hosts/ports/booleans stay printable).
_CREDENTIAL_KEY_DENY: frozenset[str] = frozenset(
    {
        "DASHBOARD_USERNAME",
        "POSTGRES_USER",
        "POSTGRES_HOST",
        "POSTGRES_PORT",
        "POSTGRES_DB",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_ADMIN_EMAIL",
        "SMTP_SENDER_NAME",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_ENABLED",
        "SITE_URL",
        "API_EXTERNAL_URL",
        "SUPABASE_PUBLIC_URL",
        "STUDIO_DEFAULT_ORGANIZATION",
        "STUDIO_DEFAULT_PROJECT",
    }
)


def _key_is_credential_class(key: str) -> bool:
    if key in _CREDENTIAL_KEY_DENY:
        return False
    if key in CREDENTIAL_KEY_EXACT:
        return True
    ku = key.upper()
    if ku.startswith("GOTRUE_EXTERNAL_") and ku.endswith("_SECRET"):
        return True
    if ku.startswith("GOTRUE_EXTERNAL_") and ku.endswith("_CLIENT_SECRET"):
        return True
    if any(ku.endswith(suf) for suf in _CREDENTIAL_KEY_SUFFIXES):
        return True
    # Explicit SMTP_* password/secret variants already covered; also SMTP_AUTH tokens.
    if ku.startswith("SMTP_") and any(s in ku for s in ("PASS", "SECRET", "TOKEN", "KEY")):
        if ku in {"SMTP_HOST", "SMTP_PORT", "SMTP_ADMIN_EMAIL", "SMTP_SENDER_NAME"}:
            return False
        return True
    return False


def secret_values_for_redaction(env: dict[str, str]) -> list[str]:
    """Return configured credential values eligible for exact-value diagnostic redaction.

    Covers explicit credential-key classes (passwords, JWT/admin/service secrets,
    SMTP credentials, OAuth/provider secrets/tokens, dashboard password, and other
    supported secret/token keys present in the project env). Short/trivial values
    are filtered so ordinary diagnostic text is not corrupted; URL userinfo is
    always handled separately by Redactor.
    """
    from sbfleet.process import value_eligible_for_exact_redaction

    out: list[str] = []
    seen: set[str] = set()
    for key, val in env.items():
        if not _key_is_credential_class(key):
            continue
        if not value_eligible_for_exact_redaction(val):
            continue
        if val in seen:
            continue
        seen.add(val)
        out.append(val)
    return out
