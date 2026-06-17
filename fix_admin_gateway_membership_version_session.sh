#!/usr/bin/env bash
set -euo pipefail

echo "==> Fixing admin gateway governed session issuance to include membership_version"

python - <<'PY'
from pathlib import Path
import re
import sys

targets = [
    Path("admin_gateway/routers/identity.py"),
    Path("admin_gateway/identity/invitation_flow.py"),
    Path("admin_gateway/auth/session.py"),
]

for p in targets:
    if p.exists():
        print(f"--- {p}")
        text = p.read_text()
        for m in re.finditer(r"create_session\(|Session\(", text):
            start = max(0, m.start() - 350)
            end = min(len(text), m.end() + 700)
            print(text[start:end])
            print("-----")

PY

python - <<'PY'
from pathlib import Path
import re

p = Path("admin_gateway/routers/identity.py")
text = p.read_text()

# Case 1: create_session(...) call has membership_id but no membership_version.
pattern = re.compile(
    r"(create_session\(\s*(?:.|\n)*?membership_id\s*=\s*([^,\n\)]+),\s*)(?!membership_version\s*=)",
    re.MULTILINE,
)

def repl(match: re.Match[str]) -> str:
    membership_expr = match.group(2).strip()
    return match.group(1) + f"membership_version=getattr({membership_expr}, 'membership_version', 1),\n        "

new_text = pattern.sub(repl, text)

# Case 2: Session(...) constructor directly has membership_id but no membership_version.
pattern2 = re.compile(
    r"(Session\(\s*(?:.|\n)*?membership_id\s*=\s*([^,\n\)]+),\s*)(?!membership_version\s*=)",
    re.MULTILINE,
)

def repl2(match: re.Match[str]) -> str:
    membership_expr = match.group(2).strip()
    return match.group(1) + f"membership_version=getattr({membership_expr}, 'membership_version', 1),\n        "

new_text = pattern2.sub(repl2, new_text)

if new_text == text:
    print("No automatic patch applied to admin_gateway/routers/identity.py")
else:
    p.write_text(new_text)
    print("Patched admin_gateway/routers/identity.py")
PY

echo "==> Show relevant diff"
git diff -- admin_gateway/routers/identity.py admin_gateway/identity/invitation_flow.py admin_gateway/auth/session.py

echo "==> Run failing test"
pytest tests/test_admin_gateway_identity_enforcement.py::test_http_gateway_fails_closed_without_adapter_then_issues_scoped_session -q

echo "==> Run targeted versioning tests"
pytest tests/security/test_membership_versioning.py -q
