from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

DEFAULT_BANNED_PATTERNS: list[str] = [
    r"^python\s+scripts/.*$",
    r"^make\s+.*$",
    r"^✅\s+.*$",
    r"^Traceback \(most recent call last\):",
    r"^PYint\(",
    r"^PY\s+.*$",  # heredoc terminator followed by garbage
]

_RX_DEFAULT = re.compile(
    "|".join(f"(?:{p})" for p in DEFAULT_BANNED_PATTERNS), re.MULTILINE
)


def _atomic_write_text(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=dest.name + ".", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="write_file.py",
        description="Atomic write stdin to a file with paste-garbage guard.",
    )
    ap.add_argument("path", help="Destination path")
    ap.add_argument(
        "--no-guard", action="store_true", help="Disable paste-garbage detection"
    )
    ap.add_argument(
        "--allow",
        action="append",
        default=[],
        help="Regex patterns to allow (advanced)",
    )
    ap.add_argument(
        "--require",
        action="append",
        default=[],
        help="Regex patterns that must appear (advanced)",
    )
    args = ap.parse_args(argv)

    dest = Path(args.path)
    if dest.is_absolute():
        print("ERROR: Refusing to write to an absolute path.", file=sys.stderr)
        return 2

    content = sys.stdin.read()
    if not content:
        print("ERROR: No stdin content received.", file=sys.stderr)
        return 2

    for pat in args.require:
        if not re.search(pat, content, flags=re.MULTILINE):
            print(f"ERROR: --require pattern not found: {pat!r}", file=sys.stderr)
            return 2

    if not args.no_guard:
        allow_rx = (
            re.compile("|".join(f"(?:{p})" for p in args.allow), re.MULTILINE)
            if args.allow
            else None
        )
        if _RX_DEFAULT.search(content):
            if allow_rx and allow_rx.search(content):
                pass
            else:
                print(
                    "ERROR: Detected terminal paste-garbage in content. Refusing to write.",
                    file=sys.stderr,
                )
                print(
                    "Hint: do NOT paste command output into file content.",
                    file=sys.stderr,
                )
                return 3

    _atomic_write_text(dest, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
