#!/usr/bin/env bash
# Remove managed SBfleet software install. Never deletes fleet data or foreign binaries.
set -euo pipefail

HOME="${HOME:-}"
if [[ -z "${HOME}" ]]; then
  echo "error: HOME is unset" >&2
  exit 4
fi

SOFT_ROOT="${SBFLEET_SOFTWARE_ROOT_BASE:-${HOME}/.local/lib/sbfleet}"
BIN_DIR="${HOME}/.local/bin"
SHIM="${BIN_DIR}/sbfleet"

contained_under() {
  local path="$1"
  local root="$2"
  case "$(readlink -f "${path}" 2>/dev/null || true)" in
    "${root}"|"${root}"/*) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ -L "${SHIM}" ]]; then
  if contained_under "${SHIM}" "${SOFT_ROOT}"; then
    rm -f "${SHIM}"
    echo "Removed managed shim ${SHIM}"
  else
    echo "warning: leaving ${SHIM} (target not under ${SOFT_ROOT})" >&2
  fi
elif [[ -e "${SHIM}" ]]; then
  echo "warning: leaving ${SHIM} (not a managed symlink)" >&2
fi

# Never delete arbitrary paths from install.json — only the known software root.
if [[ -d "${SOFT_ROOT}" ]]; then
  # Refuse if SOFT_ROOT escapes HOME/.local/lib/sbfleet default unless explicitly overridden.
  resolved="$(readlink -f "${SOFT_ROOT}")"
  expected_default="$(readlink -f "${HOME}/.local/lib/sbfleet")"
  if [[ -n "${SBFLEET_SOFTWARE_ROOT_BASE:-}" ]]; then
    :
  elif [[ "${resolved}" != "${expected_default}" ]]; then
    echo "error: refuse to delete unexpected software root ${resolved}" >&2
    exit 4
  fi
  rm -rf "${SOFT_ROOT}"
  echo "Removed ${SOFT_ROOT}"
else
  echo "No software root at ${SOFT_ROOT}"
fi

echo "Fleet data under ~/.local/share/sbfleet was not modified."
echo "Docker resources were not modified."
