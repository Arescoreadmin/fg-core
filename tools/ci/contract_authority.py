#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

MARKER_RE = re.compile(r"(Contract-Authority-SHA256:\s*)([0-9a-f]{64})", re.IGNORECASE)

# Hard excludes for filesystem fallback scan
EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".turbo",
}

# Patterns we consider "contract authority inputs"
DEFAULT_GLOB_PATTERNS = [
    "*openapi*.json",
    "*OpenAPI*.json",
    "*contract*.json",
    "*contracts*.json",
]

# Prefer these paths when multiple candidates exist
PREFERRED_PREFIXES = (
    "artifacts/",
    "contracts/",
    "contract/",
    "openapi/",
    "api/",
)


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"Failed to parse JSON: {path} ({e})") from e


def _is_excluded_path(p: str) -> bool:
    parts = Path(p).parts
    return any(part in EXCLUDE_DIRS for part in parts)


def _git_ls_files() -> list[str]:
    """
    Return git-tracked files (relative paths). If git isn't available, return [].
    """
    try:
        out = subprocess.check_output(["git", "ls-files"], text=True)
        files = [line.strip() for line in out.splitlines() if line.strip()]
        return files
    except Exception:
        return []


def _matches_any_pattern(path: str, patterns: list[str]) -> bool:
    base = Path(path).name
    for pat in patterns:
        if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(base, pat):
            return True
    return False


def _rank_path(path: str) -> tuple[int, str]:
    """
    Lower rank is better.
    Prefer artifacts/contracts/openapi-ish things, then shorter paths.
    """
    pref = 9
    for i, px in enumerate(PREFERRED_PREFIXES):
        if path.startswith(px):
            pref = i
            break
    return (pref, path)


def _expand_explicit(files_or_dirs: list[str]) -> list[Path]:
    out: list[Path] = []
    for s in files_or_dirs:
        p = Path(s)
        if p.is_dir():
            for j in sorted(p.rglob("*.json")):
                if j.is_file() and not _is_excluded_path(str(j)):
                    out.append(j)
        else:
            if p.exists() and p.is_file():
                out.append(p)
    # de-dupe
    uniq: dict[str, Path] = {}
    for p in out:
        uniq[str(p.resolve())] = p
    return sorted(uniq.values(), key=lambda x: x.as_posix())


def _gather_contract_files(
    explicit: list[str] | None,
    patterns: list[str],
    debug: bool,
) -> list[Path]:
    """
    Discovery order:
      1) explicit --files
      2) env FG_CONTRACT_AUTHORITY_FILES (space/comma-separated)
      3) git ls-files filter (fast + accurate)
      4) filesystem fallback scan (excluding junk dirs)
    """
    if explicit:
        files = _expand_explicit(explicit)
        if debug:
            print(f"[debug] explicit inputs -> {len(files)} files", file=sys.stderr)
        return files

    env_files = (os.getenv("FG_CONTRACT_AUTHORITY_FILES") or "").strip()
    if env_files:
        parts = [p for p in re.split(r"[,\s]+", env_files) if p]
        files = _expand_explicit(parts)
        if debug:
            print(f"[debug] env inputs -> {len(files)} files", file=sys.stderr)
        return files

    tracked = _git_ls_files()
    candidates: list[str] = []
    if tracked:
        for f in tracked:
            if _is_excluded_path(f):
                continue
            if not f.endswith(".json"):
                continue
            if _matches_any_pattern(f, patterns):
                candidates.append(f)

        candidates = sorted(set(candidates), key=_rank_path)
        paths = [Path(c) for c in candidates if Path(c).exists()]
        if debug:
            print(f"[debug] git discovery -> {len(paths)} files", file=sys.stderr)
            for p in paths[:30]:
                print(f"[debug]   {p}", file=sys.stderr)
            if len(paths) > 30:
                print(f"[debug]   ... (+{len(paths) - 30} more)", file=sys.stderr)
        if paths:
            return paths

    # Filesystem fallback scan (slower, but deterministic)
    root = Path(".")
    found: list[Path] = []
    for p in root.rglob("*.json"):
        sp = str(p)
        if _is_excluded_path(sp):
            continue
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        rel = p.as_posix()
        if _matches_any_pattern(rel, patterns):
            found.append(p)

    found = sorted(set(found), key=lambda x: _rank_path(x.as_posix()))
    if debug:
        print(f"[debug] fs fallback -> {len(found)} files", file=sys.stderr)
    return found


def compute_authority_sha(files: list[Path]) -> str:
    """
    Compute a stable SHA over:
      - relative paths
      - canonical JSON content
    """
    if not files:
        raise RuntimeError(
            "No contract files found. Provide --files explicitly or set FG_CONTRACT_AUTHORITY_FILES."
        )

    items: list[dict[str, Any]] = []
    for p in files:
        rel = p.as_posix()
        obj = _read_json(p)
        payload = _canonical_json_bytes(obj)
        items.append(
            {
                "path": rel,
                "sha": _sha256_bytes(payload),
                "len": len(payload),
            }
        )

    manifest = {"version": 1, "inputs": sorted(items, key=lambda x: x["path"])}
    return _sha256_bytes(_canonical_json_bytes(manifest))


def read_marker(path: Path) -> str | None:
    txt = path.read_text(encoding="utf-8")
    m = MARKER_RE.search(txt)
    return m.group(2) if m else None


def write_marker(path: Path, sha: str) -> None:
    txt = path.read_text(encoding="utf-8")
    if MARKER_RE.search(txt):
        new_txt = MARKER_RE.sub(rf"\g<1>{sha}", txt, count=1)
    else:
        new_txt = f"Contract-Authority-SHA256: {sha}\n" + txt

    if new_txt != txt:
        path.write_text(new_txt, encoding="utf-8")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Compute/verify/update Contract-Authority-SHA256 marker."
    )
    ap.add_argument("--blueprint", default="BLUEPRINT_STAGED.md")
    ap.add_argument("--files", nargs="*", help="Explicit JSON files/dirs to hash.")
    ap.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Additional glob patterns to consider (repeatable).",
    )
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--print", dest="do_print", action="store_true")
    ap.add_argument(
        "--strict", action="store_true", help="Fail if marker missing or mismatched."
    )
    ap.add_argument("--debug", action="store_true")

    args = ap.parse_args(argv)

    bp = Path(args.blueprint)
    if not bp.exists():
        print(f"Blueprint not found: {bp}", file=sys.stderr)
        return 2

    patterns = DEFAULT_GLOB_PATTERNS + list(args.pattern or [])
    files = _gather_contract_files(args.files, patterns=patterns, debug=args.debug)
    sha = compute_authority_sha(files)

    if args.do_print:
        print(sha)

    current = read_marker(bp)

    if args.write:
        write_marker(bp, sha)
        updated = read_marker(bp)
        if updated != sha:
            print("Write failed: marker did not update correctly.", file=sys.stderr)
            return 2
        print(f"Updated {bp} -> Contract-Authority-SHA256: {sha}")
        return 0

    # Verify mode
    if current is None:
        msg = f"Missing marker in {bp}. Expected: {sha}"
        if args.strict:
            print(msg, file=sys.stderr)
            return 2
        print(msg, file=sys.stderr)
        return 1

    if current != sha:
        print(f"Authority mismatch in {bp}", file=sys.stderr)
        print(f"  Found:    {current}", file=sys.stderr)
        print(f"  Expected: {sha}", file=sys.stderr)
        return 1

    print(f"Authority OK: {sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
