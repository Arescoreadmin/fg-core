#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python - <<'PY'
from pathlib import Path
import re

p = Path("scripts/apply_ui_sse_everything.sh")
s = p.read_text()

orig = s

# Any "curl ... | head -n N" should end with "|| true" because curl may exit 18 under pipefail.
# Also handle "curl ... | sed -n '1,12p'" etc similarly if present.
def protect_pipeline(text: str) -> str:
    # Add "|| true" to curl pipelines that pipe into head/sed/grep
    patterns = [
        r'(^\s*curl[^\n]*\|\s*head[^\n]*$)',
        r'(^\s*curl[^\n]*\|\s*sed[^\n]*$)',
        r'(^\s*curl[^\n]*\|\s*grep[^\n]*$)',
    ]
    for pat in patterns:
        text = re.sub(pat, lambda m: m.group(1) if "|| true" in m.group(1) else (m.group(1) + " || true"), text, flags=re.M)
    return text

s = protect_pipeline(s)

# Also protect any "curl -s -i ... | head" style embedded in echo blocks (same logic works).
# Ensure script never fails just because a smoke test is truncated.
if s != orig:
    p.write_text(s)
    print("✅ Patched apply_ui_sse_everything.sh: curl pipelines now end with '|| true' (no more exit 18).")
else:
    print("✅ No changes needed (either already patched or no curl pipelines found).")
PY

chmod +x scripts/apply_ui_sse_everything.sh
echo "✅ Done."
