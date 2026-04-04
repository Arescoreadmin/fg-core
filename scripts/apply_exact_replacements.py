#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ReplacementRule:
    file: str
    find: str
    replace: str
    count: int | None = None


def load_rules(path: Path) -> list[ReplacementRule]:
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("Rules file must be a JSON list")

    rules: list[ReplacementRule] = []
    for i, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Rule #{i} is not an object")

        file = item.get("file")
        find = item.get("find")
        replace = item.get("replace")
        count = item.get("count")

        if not isinstance(file, str) or not file.strip():
            raise ValueError(f"Rule #{i} missing valid 'file'")
        if not isinstance(find, str):
            raise ValueError(f"Rule #{i} missing valid 'find'")
        if not isinstance(replace, str):
            raise ValueError(f"Rule #{i} missing valid 'replace'")
        if count is not None and (not isinstance(count, int) or count < 1):
            raise ValueError(f"Rule #{i} has invalid 'count'")

        rules.append(
            ReplacementRule(
                file=file,
                find=find,
                replace=replace,
                count=count,
            )
        )
    return rules


def apply_rule(
    repo_root: Path,
    rule: ReplacementRule,
    dry_run: bool,
    make_backup: bool,
) -> tuple[bool, str]:
    target = repo_root / rule.file
    if not target.exists():
        return False, f"missing file: {rule.file}"

    original = target.read_text()
    occurrences = original.count(rule.find)

    if occurrences == 0:
        return False, f"no match: {rule.file}"

    if rule.count is not None and occurrences < rule.count:
        return (
            False,
            f"expected at least {rule.count} occurrence(s), found {occurrences}: {rule.file}",
        )

    replace_count = rule.count if rule.count is not None else occurrences
    updated = original.replace(rule.find, rule.replace, replace_count)

    if updated == original:
        return False, f"no change produced: {rule.file}"

    if dry_run:
        return True, f"would update {rule.file} ({replace_count} replacement(s))"

    if make_backup:
        backup = target.with_suffix(target.suffix + ".bak")
        shutil.copy2(target, backup)

    target.write_text(updated)
    return True, f"updated {rule.file} ({replace_count} replacement(s))"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply exact text replacements safely across repo files."
    )
    parser.add_argument(
        "rules",
        help="Path to JSON rules file",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root (default: current directory)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually write changes. Without this flag, runs in dry-run mode.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create .bak backups when applying changes.",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    rules_path = Path(args.rules).resolve()

    if not rules_path.exists():
        print(f"ERROR: rules file not found: {rules_path}", file=sys.stderr)
        return 2

    try:
        rules = load_rules(rules_path)
    except Exception as exc:
        print(f"ERROR: failed to load rules: {exc}", file=sys.stderr)
        return 2

    dry_run = not args.apply
    make_backup = not args.no_backup

    failures = 0
    applied = 0

    for rule in rules:
        ok, message = apply_rule(
            repo_root=repo_root,
            rule=rule,
            dry_run=dry_run,
            make_backup=make_backup,
        )
        prefix = "OK" if ok else "FAIL"
        print(f"[{prefix}] {message}")
        if ok:
            applied += 1
        else:
            failures += 1

    print(
        f"\nSummary: rules={len(rules)} succeeded={applied} failed={failures} mode={'apply' if args.apply else 'dry-run'}"
    )

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
