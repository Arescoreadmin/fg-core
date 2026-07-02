#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


REQUIRED_DOCS = (
    "docs/architecture/MCIM_18_6_MASTER_COMMAND_INFORMATION_MODEL.md",
    "docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md",
    "docs/architecture/MCIM_18_6_VALIDATION_CHECKLIST.md",
)

REQUIRED_SECTIONS = (
    "## Section 1 - Executive Summary",
    "## Section 2 - Canonical Capability Registry",
    "## Section 3 - Authority-to-Surface Matrix",
    "## Section 4 - Screen Registry",
    "## Section 5 - Widget Registry",
    "## Section 6 - Action Registry",
    "## Section 7 - State Ownership Map",
    "## Section 8 - Source-of-Truth Map",
    "## Section 9 - Workflow Map",
    "## Section 10 - Persona Model",
    "## Section 11 - Navigation Classification Model",
    "## Section 12 - Module Lifecycle Map",
    "## Section 13 - Technical Debt Ranking",
    "## Section 14 - Proposed 18.6 PR Breakdown",
    "## Section 15 - Validation Rules for Future UI PRs",
    "## Section 16 - Machine-Readable Appendix",
)

REQUIRED_JSON_BLOCKS = (
    "capability_registry",
    "screen_registry",
    "action_registry",
    "state_ownership",
    "navigation_classification",
    "module_lifecycle",
    "technical_debt",
)

ALLOWED_CHANGED_PATHS = {
    "docs/architecture/MCIM_18_6_MASTER_COMMAND_INFORMATION_MODEL.md",
    "docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md",
    "docs/architecture/MCIM_18_6_VALIDATION_CHECKLIST.md",
    "tools/ci/check_mcim_docs.py",
    "tests/tools/test_mcim_docs.py",
}

# The repo currently uses untracked audit notes as source material for MCIM.
# They are explicitly read-only evidence inputs, not part of the deliverable set.
IGNORED_STATUS_PREFIXES = (
    "audits/",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def validate_docs_exist(root: Path) -> list[str]:
    errors: list[str] = []
    for rel in REQUIRED_DOCS:
        if not (root / rel).is_file():
            errors.append(f"missing required doc: {rel}")
    return errors


def validate_required_sections(text: str) -> list[str]:
    return [f"missing required heading: {heading}" for heading in REQUIRED_SECTIONS if heading not in text]


def extract_named_json_blocks(text: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    for name in REQUIRED_JSON_BLOCKS:
        pattern = rf"### {re.escape(name)}\s+```json\s+(.*?)\s+```"
        match = re.search(pattern, text, flags=re.DOTALL)
        if match:
            blocks[name] = match.group(1)
    return blocks


def validate_json_blocks(text: str) -> list[str]:
    errors: list[str] = []
    blocks = extract_named_json_blocks(text)
    for name in REQUIRED_JSON_BLOCKS:
        if name not in blocks:
            errors.append(f"missing JSON appendix block: {name}")
            continue
        try:
            json.loads(blocks[name])
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON in block {name}: {exc}")
    return errors


def parse_git_status(root: Path) -> list[tuple[str, str]]:
    proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    entries: list[tuple[str, str]] = []
    for raw_line in proc.stdout.splitlines():
        if not raw_line:
            continue
        status = raw_line[:2]
        path = raw_line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        entries.append((status, path))
    return entries


def validate_changed_paths(root: Path) -> list[str]:
    errors: list[str] = []
    for status, path in parse_git_status(root):
        if any(path.startswith(prefix) for prefix in IGNORED_STATUS_PREFIXES):
            continue
        if path in ALLOWED_CHANGED_PATHS:
            continue
        errors.append(f"unexpected changed path {path!r} with status {status!r}")
    return errors


def run_checks(root: Path) -> list[str]:
    errors = validate_docs_exist(root)
    master_path = root / REQUIRED_DOCS[0]
    if master_path.is_file():
        text = read_text(master_path)
        errors.extend(validate_required_sections(text))
        errors.extend(validate_json_blocks(text))
    errors.extend(validate_changed_paths(root))
    return errors


def main() -> int:
    root = repo_root()
    errors = run_checks(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("MCIM docs check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
