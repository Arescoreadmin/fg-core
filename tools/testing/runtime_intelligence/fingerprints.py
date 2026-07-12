"""Stable, secret-free fingerprints for CI environment identification."""

from __future__ import annotations

import hashlib
import platform
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def commit_fingerprint() -> str:
    """SHA of HEAD commit, or 'unknown' if not in a git repo."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    sha = result.stdout.strip()
    return sha if sha else "unknown"


def dependency_fingerprint() -> str:
    """Hash of pinned requirement files (no secrets, just filenames+content)."""
    req_files = [
        REPO_ROOT / "requirements.txt",
        REPO_ROOT / "requirements-dev.txt",
        REPO_ROOT / "constraints.txt",
    ]
    h = hashlib.sha256()
    for f in sorted(req_files):
        if f.exists():
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()[:16]


def environment_fingerprint() -> str:
    """Hash of Python version + platform. No env vars, no tokens."""
    h = hashlib.sha256()
    h.update(sys.version.encode())
    h.update(platform.system().encode())
    h.update(platform.machine().encode())
    return h.hexdigest()[:16]


def selector_fingerprint(selector: str) -> str:
    """Hash of pytest selector expression."""
    return hashlib.sha256(selector.encode()).hexdigest()[:16]
