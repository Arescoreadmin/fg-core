#!/usr/bin/env bash
set -euo pipefail

FILE="api/auth_scopes/resolution.py"
test -f "$FILE" || { echo "ERROR: $FILE not found"; exit 2; }

python - <<'PY'
from __future__ import annotations
from pathlib import Path
import re

p = Path("api/auth_scopes/resolution.py")
src = p.read_text(encoding="utf-8")

# If already present, do nothing.
if re.search(r"(?m)^\s*_security_log\s*=\s*logging\.getLogger\(\s*['\"]frostgate\.security['\"]\s*\)\s*$", src):
    print("OK: _security_log already present")
    raise SystemExit(0)

# Insert after primary logger if present; otherwise after first "import logging".
insert = "\n_security_log = logging.getLogger(\"frostgate.security\")\n"

m = re.search(r"(?m)^(log\s*=\s*logging\.getLogger\(\s*['\"]frostgate['\"]\s*\)\s*)$", src)
if m:
    src = src[:m.end()] + insert + src[m.end():]
else:
    m2 = re.search(r"(?m)^\s*import\s+logging\s*$", src)
    if not m2:
        raise SystemExit("ERROR: could not find 'import logging' or 'log = logging.getLogger(...)' to anchor insertion")
    src = src[:m2.end()] + insert + src[m2.end():]

p.write_text(src, encoding="utf-8")
print("OK: inserted _security_log logger")
PY

ruff check api/auth_scopes/resolution.py
ruff format api/auth_scopes/resolution.py
