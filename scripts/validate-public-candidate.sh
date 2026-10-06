#!/usr/bin/env bash
# Scan an exported public candidate tree (filename + content workflow terms).
set -euo pipefail

DIR="${1:-}"
if [[ -z "$DIR" || ! -d "$DIR" ]]; then
  echo "usage: scripts/validate-public-candidate.sh CANDIDATE_DIR" >&2
  exit 2
fi

DIR="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$DIR")"
MANIFEST="$DIR/EXPORT_MANIFEST.json"

if [[ ! -f "$MANIFEST" ]]; then
  echo "error: missing EXPORT_MANIFEST.json" >&2
  exit 3
fi

if [[ -e "$DIR/.git" ]]; then
  echo "error: candidate contains .git" >&2
  exit 4
fi

export CANDIDATE_DIR="$DIR"
python3 <<'PY'
import json, os, re, sys
from pathlib import Path

root = Path(os.environ["CANDIDATE_DIR"])
manifest = json.loads((root / "EXPORT_MANIFEST.json").read_text(encoding="utf-8"))

# Public manifest must not retain private development provenance.
private_keys = [k for k in ("source_commit", "source_branch", "source_repo") if k in manifest]
if private_keys:
    print(f"error: public EXPORT_MANIFEST.json contains private provenance keys: {private_keys}")
    sys.exit(1)

filename_re = re.compile(
    r"(astra|cursor|chatgpt|openai|aud-|hardening|read_first|handoff|re-audit|recheck|run_[abcd]|run2d)",
    re.I,
)
content_res = [
    (re.compile(r"\bAstra\b"), "Astra"),
    (re.compile(r"\bCursor\b"), "Cursor"),
    (re.compile(r"\bChatGPT\b"), "ChatGPT"),
    (re.compile(r"\bOpenAI\b(?!_API_KEY)"), "OpenAI"),
    (re.compile(r"\bAUD-\d", re.I), "AUD-"),
    (re.compile(r"\bHardening Run\b", re.I), "Hardening Run"),
    (re.compile(r"Run [ABCD]\b"), "Run letter"),
    (re.compile(r"/home/pepinko"), "home path"),
    (re.compile(r"\bleadforge\b", re.I), "leadforge"),
    (re.compile(r"sweetmoments", re.I), "sweetmoments"),
    (re.compile(r"\bSBF-\d", re.I), "SBF-"),
    (re.compile(r"\bIMP-\d", re.I), "IMP-"),
    # Actual private SHA values only (40 hex), not the field name documentation.
    (re.compile(r"\b[0-9a-f]{40}\b"), "git-sha-40"),
]

exceptions = {"OPENAI_API_KEY", "openai_api_url"}
# Upstream pin SHAs that are intentionally public product facts.
# Upstream pin SHAs that are intentionally public product facts (from source pins).
public_sha_allow: set[str] = set()
upstream_py = root / "src" / "sbfleet" / "upstream.py"
if upstream_py.is_file():
    for m in re.finditer(r'"([0-9a-f]{40})"', upstream_py.read_text(encoding="utf-8")):
        public_sha_allow.add(m.group(1))
# Documented annotated-tag object for current pin (not always in upstream.py).
public_sha_allow.update(
    {
        "47111f95a43ffcc20ab288e29c48ce0b80174bd6",
        "70b42b8bf64b8cf1fd14c02c013d99dd655626e2",
    }
)
# If private provenance sidecar exists beside candidate, its SHA must NOT appear in tree.
sidecar = root.parent / f"{root.name}.PRIVATE_PROVENANCE.json"
private_source_sha = None
if sidecar.is_file():
    private_source_sha = json.loads(sidecar.read_text(encoding="utf-8")).get("source_commit")


# Real age identity material is long; short test stubs are not secret artifacts.
age_real = re.compile(r"AGE-SECRET-KEY-1[A-Za-z0-9]{20,}")
pem_real = re.compile(r"BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY")

fname_hits = []
content_hits = []
secret_hits = []
symlink_hits = []
for path in sorted(root.rglob("*")):
    rel = path.relative_to(root).as_posix()
    if path.is_symlink():
        symlink_hits.append(rel)
        continue
    if not path.is_file() or path.name.startswith("."):
        continue
    if rel in (
        "EXPORT_MANIFEST.sha256",
        "scripts/validate-public-candidate.sh",
        "packaging/public-deny-patterns.txt",
    ):
        continue
    if filename_re.search(rel):
        fname_hits.append(rel)
    name_l = path.name.lower()
    if name_l.endswith((".age", ".pem")) and not name_l.endswith(".py"):
        secret_hits.append(rel)
    if name_l == ".env" or name_l.endswith(".env"):
        secret_hits.append(rel)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    if age_real.search(text) or pem_real.search(text):
        secret_hits.append(rel)
    if rel == "EXPORT_MANIFEST.json":
        continue  # already checked keys; file list may include public pin SHAs in paths? no
    needles = (
        "Astra",
        "Cursor",
        "ChatGPT",
        "OpenAI",
        "AUD-",
        "Hardening",
        "Run A",
        "/home/pepinko",
        "leadforge",
        "sweetmoments",
        "SBF-",
        "IMP-",
    )
    has_needle = any(c in text for c in needles) or bool(re.search(r"\b[0-9a-f]{40}\b", text))
    if not has_needle:
        continue
    for rx, label in content_res:
        for m in rx.finditer(text):
            frag = text[max(0, m.start() - 20) : m.end() + 20]
            if any(ex in frag for ex in exceptions):
                continue
            if label == "git-sha-40" and m.group(0) in public_sha_allow:
                continue
            # Fake/fixture SHAs of all zeros / all a's etc. in tests are OK.
            if label == "git-sha-40" and len(set(m.group(0))) == 1:
                continue
            if label == "git-sha-40" and private_source_sha and m.group(0) == private_source_sha:
                content_hits.append((rel, "private-source-sha", m.group(0)[:12] + "…"))
                break
            if label == "git-sha-40" and private_source_sha is None:
                # Without sidecar, still ignore known public pins; other SHAs in product
                # docs are treated as upstream facts only if already allowlisted above.
                # Remaining unknown SHAs fail closed for operator review.
                pass
            content_hits.append((rel, label, m.group(0)[:48]))
            break

print("=== Public candidate validation ===")
print(f"exported_file_count: {manifest.get('file_count', len(manifest.get('files', [])))}")
print(f"release_version: {manifest.get('release_version')}")
print(f"public_manifest_private_keys: {private_keys or 'none'}")
print(f"filename_workflow_hits: {len(fname_hits)}")
for h in fname_hits[:20]:
    print(f"  fname: {h}")
print(f"content_workflow_hits: {len(content_hits)}")
for h in content_hits[:40]:
    print(f"  content: {h[0]} ({h[1]}) {h[2]!r}")
print(f"secret_artifact_hits: {len(secret_hits)}")
for h in secret_hits[:10]:
    print(f"  secret: {h}")
print(f"symlink_hits: {len(symlink_hits)}")

failed = bool(fname_hits or content_hits or secret_hits or symlink_hits or private_keys)
if failed:
    sys.exit(1)
print("OK: zero internal-workflow / private-provenance / secret / symlink hits")
PY
