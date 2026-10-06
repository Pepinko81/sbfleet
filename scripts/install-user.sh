#!/usr/bin/env bash
# Transactional user-level SBfleet install (no sudo).
# Public shim: ~/.local/bin/sbfleet only. Managed tools stay under ~/.local/lib/sbfleet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOME="${HOME:-}"
if [[ -z "${HOME}" ]]; then
  echo "error: HOME is unset" >&2
  exit 4
fi

SOFT_ROOT="${SBFLEET_SOFTWARE_ROOT_BASE:-${HOME}/.local/lib/sbfleet}"
BIN_DIR="${HOME}/.local/bin"
CURRENT="${SOFT_ROOT}/current"
CONFIGURE_PATH=0
SKIP_TOOLS=0
SOURCE="${ROOT}"
STAGE_ID="staging-$(date +%s)-$$"
STAGE="${SOFT_ROOT}/${STAGE_ID}"
PROMOTED=0
# Operator shell PATH at installer start (cannot mutate the parent shell).
OPERATOR_PATH="${PATH:-}"

usage() {
  cat <<'EOF'
Usage: scripts/install-user.sh [options]

  --source DIR       Checkout to install (default: repository containing this script)
  --skip-tools       Install sbfleet only (no age/supabase download)
  --configure-path   Append ~/.local/bin to ~/.profile when missing (login shells)
  --help             Show this help

Environment:
  SBFLEET_SOFTWARE_ROOT_BASE  Override software base (default: ~/.local/lib/sbfleet)
  SBFLEET_TOOL_CACHE          Optional directory of pre-downloaded pin archives
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE="$(cd "$2" && pwd)"
      shift 2
      ;;
    --skip-tools)
      SKIP_TOOLS=1
      shift
      ;;
    --configure-path)
      CONFIGURE_PATH=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "${SOURCE}/pyproject.toml" ]]; then
  echo "error: source is not an sbfleet checkout: ${SOURCE}" >&2
  exit 2
fi

map_arch() {
  local m
  m="$(uname -m)"
  case "${m}" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *)
      echo "error: unsupported architecture: ${m} (need linux amd64 or arm64)" >&2
      exit 4
      ;;
  esac
}

ARCH="$(map_arch)"
OS="linux"

mkdir -p "${SOFT_ROOT}" "${BIN_DIR}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/venv" "${STAGE}/tools" "${STAGE}/download"

cleanup_stage_on_fail() {
  local ec=$?
  if [[ "${PROMOTED}" -eq 0 && -d "${STAGE}" ]]; then
    echo "error: install failed; previous install left unchanged; removing staging" >&2
    rm -rf "${STAGE}"
  fi
  exit "${ec}"
}
trap cleanup_stage_on_fail EXIT

echo "==> Creating staging venv at ${STAGE}/venv"
python3 -m venv "${STAGE}/venv"
"${STAGE}/venv/bin/python" -m pip install -U pip
echo "==> Installing sbfleet from ${SOURCE} (PEP 517 isolated build)"
"${STAGE}/venv/bin/python" -m pip install "${SOURCE}"

# Ensure tomllib/tomli available for pin parsing (host python for helper).
PIN_PY=python3
if ! python3 -c 'import tomllib' 2>/dev/null; then
  if ! python3 -c 'import tomli' 2>/dev/null; then
    "${STAGE}/venv/bin/python" -m pip install -q 'tomli>=2.0.1'
    PIN_PY="${STAGE}/venv/bin/python"
  fi
fi

export SBFLEET_INSTALL_SOURCE="${SOURCE}"
export SBFLEET_INSTALL_STAGE="${STAGE}"
export SBFLEET_INSTALL_OS="${OS}"
export SBFLEET_INSTALL_ARCH="${ARCH}"
"${PIN_PY}" - <<'PY'
import json, os
from pathlib import Path
stage = Path(os.environ["SBFLEET_INSTALL_STAGE"])
meta = {
    "format_version": 1,
    "package": "sbfleet",
    "source": os.environ["SBFLEET_INSTALL_SOURCE"],
    "prefix": str(stage),
    "tools": {},
}
(stage / "install.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
PY

install_pinned_tool() {
  local tool="$1"
  local version="$2"
  local dest_rel="$3"
  export SBFLEET_INSTALL_TOOL="${tool}"
  export SBFLEET_INSTALL_TOOL_VERSION="${version}"
  export SBFLEET_INSTALL_DEST_REL="${dest_rel}"
  "${PIN_PY}" - <<'PY'
import hashlib, json, os, sys, tarfile, urllib.request
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore

source = Path(os.environ["SBFLEET_INSTALL_SOURCE"])
stage = Path(os.environ["SBFLEET_INSTALL_STAGE"])
tool = os.environ["SBFLEET_INSTALL_TOOL"]
version = os.environ["SBFLEET_INSTALL_TOOL_VERSION"]
os_name = os.environ["SBFLEET_INSTALL_OS"]
arch = os.environ["SBFLEET_INSTALL_ARCH"]
dest = stage / os.environ["SBFLEET_INSTALL_DEST_REL"]

pin_file = source / "packaging" / "tool-pins.toml"
data = tomllib.loads(pin_file.read_text(encoding="utf-8"))
try:
    entry = data[tool][version][os_name][arch]
except KeyError as exc:
    print(f"error: pin missing for {tool} {version} {os_name}/{arch}: {exc}", file=sys.stderr)
    sys.exit(4)

url = entry["url"]
expect = entry["sha256"]
member = entry["archive_member"]
name = url.rsplit("/", 1)[-1]
archive = stage / "download" / name
cache = os.environ.get("SBFLEET_TOOL_CACHE", "").strip()
if cache:
    cached = Path(cache) / name
    if not cached.is_file():
        print(f"error: missing cached archive {cached}", file=sys.stderr)
        sys.exit(4)
    archive.write_bytes(cached.read_bytes())
else:
    print(f"==> Downloading {url}")
    urllib.request.urlretrieve(url, archive)  # noqa: S310 — URL from committed pin manifest

digest = hashlib.sha256(archive.read_bytes()).hexdigest()
if digest != expect:
    print(f"error: sha256 mismatch for {name}: got {digest} want {expect}", file=sys.stderr)
    sys.exit(4)

dest.mkdir(parents=True, exist_ok=True)
with tarfile.open(archive, "r:gz") as tf:
    members = [member] + list(entry.get("extra_members") or [])
    for m in members:
        info = tf.getmember(m)
        out = dest / Path(m).name
        fsrc = tf.extractfile(info)
        if fsrc is None:
            print(f"error: missing archive member {m}", file=sys.stderr)
            sys.exit(4)
        out.write_bytes(fsrc.read())
        out.chmod(0o755)

install_json = stage / "install.json"
meta = json.loads(install_json.read_text(encoding="utf-8"))
meta.setdefault("tools", {})[tool] = {
    "version": version,
    "sha256": expect,
    "path": str(dest / Path(member).name),
}
install_json.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
print(f"OK: {tool} {version} -> {dest}")
PY
}

if [[ "${SKIP_TOOLS}" -eq 0 ]]; then
  install_pinned_tool supabase "2.118.0" "tools/supabase/2.118.0"
  install_pinned_tool age "1.3.2" "tools/age/1.3.2"
fi

STAGING_SBFLEET="${STAGE}/venv/bin/sbfleet"
if [[ ! -x "${STAGING_SBFLEET}" ]]; then
  echo "error: staging sbfleet missing at ${STAGING_SBFLEET}" >&2
  exit 4
fi

echo "==> Staging self-check"
SBFLEET_SOFTWARE_ROOT="${STAGE}" "${STAGING_SBFLEET}" --version >/dev/null

echo "==> Promoting staging -> current (symlink; venv directory never moves)"
# Keep the staging directory in place and flip `current` to point at it so
# console-script shebangs (absolute venv python paths) remain valid.
OLD_TARGET=""
if [[ -L "${CURRENT}" ]]; then
  OLD_TARGET="$(readlink "${CURRENT}" || true)"
elif [[ -d "${CURRENT}" && ! -L "${CURRENT}" ]]; then
  # Migrate legacy directory-shaped current → rename aside, then symlink.
  LEGACY="${SOFT_ROOT}/legacy-current-$(date +%s)"
  mv "${CURRENT}" "${LEGACY}"
  OLD_TARGET="$(basename "${LEGACY}")"
fi

ln -sfn "${STAGE_ID}" "${SOFT_ROOT}/current.new"
mv -Tf "${SOFT_ROOT}/current.new" "${CURRENT}"
PROMOTED=1
trap - EXIT

TARGET_SHIM="${BIN_DIR}/sbfleet"
MANAGED_BIN="${CURRENT}/venv/bin/sbfleet"
rollback_promote() {
  if [[ -n "${OLD_TARGET}" ]]; then
    ln -sfn "${OLD_TARGET}" "${SOFT_ROOT}/current.new"
    mv -Tf "${SOFT_ROOT}/current.new" "${CURRENT}"
  fi
  rm -rf "${STAGE}"
}

if [[ -e "${TARGET_SHIM}" || -L "${TARGET_SHIM}" ]]; then
  if [[ -L "${TARGET_SHIM}" ]]; then
    resolved="$(readlink -f "${TARGET_SHIM}" || true)"
    case "${resolved}" in
      "${SOFT_ROOT}"/*) ln -sfn "${MANAGED_BIN}" "${TARGET_SHIM}" ;;
      *)
        echo "error: ${TARGET_SHIM} exists and is not an sbfleet-managed symlink; refuse to overwrite" >&2
        rollback_promote
        exit 4
        ;;
    esac
  else
    echo "error: ${TARGET_SHIM} exists and is not a symlink; refuse to overwrite" >&2
    rollback_promote
    exit 4
  fi
else
  ln -sfn "${MANAGED_BIN}" "${TARGET_SHIM}"
fi

# Drop previous generation after successful shim update.
if [[ -n "${OLD_TARGET}" && "${OLD_TARGET}" != "${STAGE_ID}" ]]; then
  if [[ "${OLD_TARGET}" != /* ]]; then
    rm -rf "${SOFT_ROOT}/${OLD_TARGET}"
  fi
fi

if [[ "${CONFIGURE_PATH}" -eq 1 ]]; then
  PROFILE="${HOME}/.profile"
  MARKER="# sbfleet: ensure ~/.local/bin on PATH"
  if [[ -f "${PROFILE}" && -O "${PROFILE}" && ! -L "${PROFILE}" ]]; then
    if ! grep -qF "${MARKER}" "${PROFILE}" 2>/dev/null \
      && ! grep -q '\.local/bin' "${PROFILE}" 2>/dev/null; then
      cat >> "${PROFILE}" <<'EOF'

# sbfleet: ensure ~/.local/bin on PATH
if [ -d "$HOME/.local/bin" ]; then
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) PATH="$HOME/.local/bin:$PATH" ;;
  esac
fi
EOF
      echo "==> Appended PATH stanza to ${PROFILE}"
    fi
  else
    echo "warning: refuse to edit ${PROFILE} (missing, not owned, or symlink)" >&2
  fi
fi

echo "==> Acceptance probes"
ARTIFACTS_READY=0
DOCKER_READY=0
BACKUP_READY=0
SANDBOX_READY=0
CURRENT_SHELL_READY=0
LOGIN_SHELL_READY=0
LOGIN_SHELL_STATUS="UNKNOWN"

# Artifact probe: clean PATH that includes the managed shim directory.
set +e
env -i HOME="${HOME}" USER="${USER:-}" PATH="/usr/bin:/bin:${BIN_DIR}" \
  /bin/sh -c 'command -v sbfleet && sbfleet --version' >/dev/null 2>&1
FS_EC=$?
OUTSIDE="$(mktemp -d)"
env -i HOME="${HOME}" USER="${USER:-}" PATH="/usr/bin:/bin:${BIN_DIR}" \
  /bin/sh -c "cd \"${OUTSIDE}\" && command -v sbfleet && sbfleet --version" >/dev/null 2>&1
OUT_EC=$?
set -e
rmdir "${OUTSIDE}" 2>/dev/null || rm -rf "${OUTSIDE}"
if [[ "${FS_EC}" -eq 0 && "${OUT_EC}" -eq 0 && -x "${TARGET_SHIM}" ]]; then
  ARTIFACTS_READY=1
fi

# Current/operator shell: inherited PATH at installer start (parent env cannot be mutated).
set +e
env -i HOME="${HOME}" USER="${USER:-}" PATH="${OPERATOR_PATH}" \
  /bin/sh -c 'command -v sbfleet && sbfleet --version' >/dev/null 2>&1
CUR_EC=$?
set -e
if [[ "${CUR_EC}" -eq 0 ]]; then
  CURRENT_SHELL_READY=1
fi

# Login-shell probe when bash is available (sources profile under HOME; no rc mutation here).
BASH_BIN="$(command -v bash || true)"
if [[ -n "${BASH_BIN}" && -x "${BASH_BIN}" ]]; then
  set +e
  env -i HOME="${HOME}" USER="${USER:-}" TERM="${TERM:-dumb}" \
    "${BASH_BIN}" -l -c 'command -v sbfleet >/dev/null 2>&1 && sbfleet --version >/dev/null 2>&1'
  LOGIN_EC=$?
  set -e
  if [[ "${LOGIN_EC}" -eq 0 ]]; then
    LOGIN_SHELL_READY=1
    LOGIN_SHELL_STATUS="YES"
  else
    LOGIN_SHELL_STATUS="NO"
  fi
else
  LOGIN_SHELL_STATUS="UNKNOWN"
fi

echo "Host prerequisite inventory:"
printf '  %-10s %s\n' "python3" "$(python3 --version 2>&1 || echo MISSING)"
printf '  %-10s %s\n' "venv" "$(python3 -c 'import venv; print("ok")' 2>&1 || echo MISSING)"
printf '  %-10s %s\n' "git" "$(git --version 2>&1 || echo MISSING)"
printf '  %-10s %s\n' "jq" "$(jq --version 2>&1 || echo MISSING)"
printf '  %-10s %s\n' "openssl" "$(openssl version 2>&1 || echo MISSING)"
printf '  %-10s %s\n' "node" "$(node --version 2>&1 || echo MISSING)"

if command -v docker >/dev/null 2>&1; then
  ENG="$(docker info --format '{{.ServerVersion}}' 2>/dev/null || true)"
  if [[ -n "${ENG}" ]]; then
    MAJOR="${ENG%%.*}"
    if [[ "${MAJOR}" =~ ^[0-9]+$ ]] && [[ "${MAJOR}" -ge 28 ]]; then
      if docker compose version >/dev/null 2>&1; then
        DOCKER_READY=1
      fi
    fi
  fi
fi

AGE_BIN="${CURRENT}/tools/age/1.3.2/age"
SUPA_BIN="${CURRENT}/tools/supabase/2.118.0/supabase"
if [[ -x "${AGE_BIN}" ]]; then
  BACKUP_READY=1
fi
if [[ -x "${SUPA_BIN}" ]] && printf '%s' "$("${SUPA_BIN}" --version 2>/dev/null || true)" | grep -q '2\.118\.0'; then
  if command -v node >/dev/null 2>&1; then
    NODE_MAJOR="$(node --version 2>/dev/null | sed 's/^v//' | cut -d. -f1 || true)"
    if [[ "${NODE_MAJOR}" =~ ^[0-9]+$ ]] && [[ "${NODE_MAJOR}" -ge 16 ]]; then
      SANDBOX_READY=1
    fi
  fi
fi

# SBFLEET CLI READY means install artifacts are usable when ~/.local/bin is on PATH.
SBFLEET_CLI_READY="${ARTIFACTS_READY}"

echo
echo "Third-party tools (Supabase CLI, age) are downloaded under the managed install tree and are licensed by their respective upstream projects. See THIRD_PARTY_NOTICES.md in the SBfleet source tree."
echo
echo "Readiness:"
echo "  INSTALLATION ARTIFACTS READY: $([[ "${ARTIFACTS_READY}" -eq 1 ]] && echo YES || echo NO)"
[[ "${SBFLEET_CLI_READY}" -eq 1 ]] && echo "  SBFLEET CLI READY: YES" || echo "  SBFLEET CLI READY: NO"
[[ "${DOCKER_READY}" -eq 1 ]] && echo "  DOCKER READY: YES" || echo "  DOCKER READY: NO — install/start Docker Engine 28+ and Compose v2"
[[ "${BACKUP_READY}" -eq 1 ]] && echo "  BACKUP READY: YES" || echo "  BACKUP READY: NO — re-run without --skip-tools (managed age 1.3.2)"
[[ "${SANDBOX_READY}" -eq 1 ]] && echo "  SANDBOX READY: YES" || echo "  SANDBOX READY: NO — need managed supabase 2.118.0 + Node >=16"

echo
echo "Shell PATH:"
if [[ "${CURRENT_SHELL_READY}" -eq 1 ]]; then
  echo "  CURRENT SHELL sbfleet: READY"
else
  echo "  CURRENT SHELL sbfleet: PENDING"
  echo "    This installer cannot change your already-open shell's PATH."
  echo "    Run in this shell:"
  echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo "    Or open a new login shell / re-login after ~/.local/bin exists."
  if [[ "${CONFIGURE_PATH}" -eq 0 ]]; then
    echo "    Optional next install: bash scripts/install-user.sh --configure-path"
  fi
fi
echo "  LOGIN SHELL sbfleet: ${LOGIN_SHELL_STATUS}"
if [[ "${LOGIN_SHELL_STATUS}" == "NO" ]]; then
  echo "    Login shell still cannot resolve sbfleet; ensure ~/.profile (or equivalent)"
  echo "    adds \$HOME/.local/bin, or export PATH as above. --configure-path is opt-in."
fi

ARTIFACT_PLANES_OK=0
if [[ "${ARTIFACTS_READY}" -eq 1 && "${DOCKER_READY}" -eq 1 && "${BACKUP_READY}" -eq 1 && "${SANDBOX_READY}" -eq 1 ]]; then
  ARTIFACT_PLANES_OK=1
fi

if [[ "${ARTIFACT_PLANES_OK}" -eq 1 && "${CURRENT_SHELL_READY}" -eq 1 ]]; then
  echo
  echo "FULL V1 READY: YES"
  exit 0
fi

echo
if [[ "${ARTIFACT_PLANES_OK}" -eq 1 && "${CURRENT_SHELL_READY}" -eq 0 ]]; then
  echo "FULL V1 READY: NO"
  echo "  Installation artifacts are READY, but current-shell command availability is PENDING."
  echo "  After: export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo "  verify: command -v sbfleet && sbfleet --version"
else
  echo "FULL V1 READY: NO"
fi
echo "Managed entrypoint (absolute): ${TARGET_SHIM}"
exit 4
