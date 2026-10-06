#!/usr/bin/env bash
# Ensure an isolated project venv with an editable install of THIS checkout.
# All verification gates should use: .venv/bin/python -m <tool> ...
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install -e '.[dev]'

.venv/bin/python - <<'PY'
from pathlib import Path
import sys
import sbfleet
from sbfleet import authority

root = Path(".").resolve()
expected = (root / "src" / "sbfleet").resolve()
pkg = Path(sbfleet.__file__).resolve()
auth = Path(authority.__file__).resolve()
if not pkg.is_relative_to(expected) or not auth.is_relative_to(expected):
    raise SystemExit(
        f"editable install does not resolve to checkout:\n"
        f"  sbfleet={pkg}\n  authority={auth}\n  expected_under={expected}"
    )
if "site-packages" in str(pkg) or "site-packages" in str(auth):
    raise SystemExit(f"refusing site-packages import: {pkg} / {auth}")
print(f"python={sys.executable}")
print(f"sbfleet={pkg}")
print(f"authority={auth}")
PY

echo "OK: run gates with: $ROOT/.venv/bin/python -m ..."
