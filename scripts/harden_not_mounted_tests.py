from __future__ import annotations

from pathlib import Path
import re

FLAGS = [
    "FG_GOVERNANCE_ENABLED",
    "FG_MISSION_ENVELOPE_ENABLED",
    "FG_RING_ROUTER_ENABLED",
    "FG_ROE_ENGINE_ENABLED",
    "FG_FORENSICS_ENABLED",
]

DEF_RE = re.compile(r"^def\s+(test_.*not_mounted_when_disabled.*)\s*\(.*\)\s*:\s*$")

def patch_file(path: Path) -> bool:
    text = path.read_text("utf-8")
    if "not_mounted_when_disabled" not in text:
        return False

    lines = text.splitlines()
    changed = False

    i = 0
    while i < len(lines):
        m = DEF_RE.match(lines[i])
        if not m:
            i += 1
            continue

        # Determine indent level for function body (assume 4 spaces)
        insert_at = i + 1
        while insert_at < len(lines) and lines[insert_at].strip() == "":
            insert_at += 1

        # If function has args without monkeypatch, skip (we can't add it safely)
        sig = lines[i]
        if "monkeypatch" not in sig:
            i += 1
            continue

        # Collect existing delenv flags in first ~60 lines after def
        existing = set()
        for k in range(i + 1, min(i + 60, len(lines))):
            mm = re.search(r"monkeypatch\.delenv\(['\"](FG_[A-Z0-9_]+)['\"],\s*raising=False\)", lines[k])
            if mm:
                existing.add(mm.group(1))

        to_add = [f"    monkeypatch.delenv({flag!r}, raising=False)" for flag in FLAGS if flag not in existing]
        if to_add:
            lines[insert_at:insert_at] = to_add
            changed = True
            i = insert_at + len(to_add)  # skip over inserted
        else:
            i += 1

    if changed:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed

def main() -> None:
    touched = []
    for p in sorted(Path("tests").rglob("test_*.py")):
        if patch_file(p):
            touched.append(str(p))

    if not touched:
        print("No changes needed.")
        return

    print("Patched:")
    for t in touched:
        print(f" - {t}")

if __name__ == "__main__":
    main()