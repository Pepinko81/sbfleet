#!/usr/bin/env bash
# Export a sanitized SBfleet public candidate tree from the private development repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ALLOWLIST="${ROOT}/packaging/public-files.txt"
DENY="${ROOT}/packaging/public-deny-patterns.txt"
OUT=""
DRY_RUN=0
ALLOW_DIRTY=0

usage() {
  cat <<EOF
Usage: scripts/export-public.sh --out DIR [options]

  --out DIR          Destination directory (must not be inside source repo)
  --dry-run          Validate and print actions without writing files
  --allow-dirty      Dev-only: skip clean working-tree check (not for releases)
  -h, --help         Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$OUT" ]]; then
  echo "error: --out DIR is required" >&2
  exit 2
fi

if [[ ! -f "$ALLOWLIST" ]]; then
  echo "error: missing allowlist: $ALLOWLIST" >&2
  exit 2
fi

cd "$ROOT"
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: not a git repository: $ROOT" >&2
  exit 2
fi

if [[ "$ALLOW_DIRTY" -eq 0 ]]; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "error: source working tree or index has uncommitted changes; commit or stash before export" >&2
    git status --short >&2 || true
    exit 3
  fi
else
  echo "warning: --allow-dirty enabled (development only; do not use for release)" >&2
fi

SOURCE_COMMIT="$(git rev-parse HEAD)"
SOURCE_BRANCH="$(git symbolic-ref -q --short HEAD || echo detached)"

OUT="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$OUT")"
ROOT_REAL="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$ROOT")"

if [[ "$OUT" == "$ROOT_REAL" ]] || [[ "$OUT" == "$ROOT_REAL/"* ]]; then
  echo "error: destination must not be inside source repository" >&2
  exit 4
fi

if [[ -e "$OUT/.git" ]]; then
  echo "error: destination contains .git" >&2
  exit 4
fi

RELEASE_VERSION="$(python3 - <<'PY' "$ROOT/pyproject.toml"
import sys, re
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
if not m:
    raise SystemExit("missing version in pyproject.toml")
print(m.group(1))
PY
)"

export REAL="$ROOT_REAL" OUT="$OUT" ALLOWLIST_FILE="$ALLOWLIST" DENY_FILE="$DENY" \
  DRY_RUN="$DRY_RUN" SOURCE_COMMIT="$SOURCE_COMMIT" SOURCE_BRANCH="$SOURCE_BRANCH" RELEASE_VERSION="$RELEASE_VERSION"

python3 <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(os.environ["REAL"])
out = Path(os.environ["OUT"])
allowlist_file = Path(os.environ["ALLOWLIST_FILE"])
deny_file = Path(os.environ["DENY_FILE"])
dry_run = os.environ["DRY_RUN"] == "1"
source_commit = os.environ["SOURCE_COMMIT"]
source_branch = os.environ["SOURCE_BRANCH"]
release_version = os.environ["RELEASE_VERSION"]

deny_substrings = [
    line.strip()
    for line in deny_file.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.strip().startswith("#")
]

allowed: set[str] = set()
for line in allowlist_file.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    allowed.add(line.replace("\\", "/"))

# Expand allowlist: if entry ends with /**, glob under root
resolved_files: list[str] = []
missing: list[str] = []
for entry in sorted(allowed):
    if entry.endswith("/**"):
        base = entry[:-3].rstrip("/")
        base_path = root / base
        if not base_path.is_dir():
            missing.append(entry)
            continue
        for p in sorted(base_path.rglob("*")):
            if p.is_file() and not p.is_symlink():
                rel = p.relative_to(root).as_posix()
                resolved_files.append(rel)
    else:
        p = root / entry
        if not p.is_file() or p.is_symlink():
            missing.append(entry)
            continue
        resolved_files.append(entry)

if missing:
    print("error: allowlist entries missing or not regular files:", file=sys.stderr)
    for m in missing:
        print(f"  {m}", file=sys.stderr)
    sys.exit(5)

resolved_files = sorted(set(resolved_files))

for rel in resolved_files:
    for pat in deny_substrings:
        if pat in rel:
            print(f"error: deny pattern {pat!r} matched allowlisted path {rel}", file=sys.stderr)
            sys.exit(6)

# Scan source tree for unexpected tracked public candidates not in list — only among resolved set is OK

def check_source_path(src: Path) -> None:
    if src.is_symlink():
        raise RuntimeError(f"symlink in source not allowed: {src.relative_to(root)}")
    if src.is_dir():
        return
    if not src.is_file():
        raise RuntimeError(f"unsupported file type: {src.relative_to(root)}")


def copy_file(src: Path, dst: Path) -> None:
    check_source_path(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dry_run:
        return
    shutil.copy2(src, dst)
    mode = src.stat().st_mode
    if mode & stat.S_IXUSR:
        dst.chmod(mode & 0o7777)


if not dry_run:
    if out.exists():
        for child in out.iterdir():
            if child.name == ".git":
                raise RuntimeError("destination contains .git")
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    out.mkdir(parents=True, exist_ok=True)

for rel in resolved_files:
    src = root / rel
    dst = out / rel
    src_res = src.resolve()
    if not str(src_res).startswith(str(root.resolve()) + os.sep) and src_res != root.resolve():
        raise RuntimeError(f"path traversal: {rel}")
    copy_file(src, dst)

# Public candidate: integrity metadata only — never private development SHAs.
public_manifest = {
    "format_version": 1,
    "product": "sbfleet",
    "release_version": release_version,
    "exported_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "file_count": len(resolved_files),
    "files": resolved_files,
}
# Private sidecar: exact private-repo provenance for maintainers (not under OUT/).
private_provenance = {
    "format_version": 1,
    "source_repo": "sbfleet",
    "source_commit": source_commit,
    "source_branch": source_branch,
    "release_version": release_version,
    "exported_at_utc": public_manifest["exported_at_utc"],
    "candidate_dir": str(out),
    "file_count": len(resolved_files),
}
# Sibling path outside the public tree.
private_path = out.parent / f"{out.name}.PRIVATE_PROVENANCE.json"

public_bytes = (json.dumps(public_manifest, indent=2) + "\n").encode("utf-8")
private_bytes = (json.dumps(private_provenance, indent=2) + "\n").encode("utf-8")
if dry_run:
    print(f"dry-run: would export {len(resolved_files)} files to {out}")
    print(f"release_version={release_version}")
    print(f"private provenance would write to {private_path} (source_commit redacted from public tree)")
else:
    (out / "EXPORT_MANIFEST.json").write_bytes(public_bytes)
    digest = hashlib.sha256(public_bytes).hexdigest()
    (out / "EXPORT_MANIFEST.sha256").write_text(digest + "\n", encoding="utf-8")
    private_path.write_bytes(private_bytes)
    print(f"exported {len(resolved_files)} files to {out}")
    print(f"EXPORT_MANIFEST.json written (sha256 {digest[:16]}…)")
    print(f"private provenance: {private_path}")

PY
