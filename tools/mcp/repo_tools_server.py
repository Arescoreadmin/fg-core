#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import subprocess
import shlex

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("repo-tools")
REPO_ROOT = Path(__file__).resolve().parents[2]

ALLOWED_TARGETS = {
    "lint",
    "typecheck",
    "test-fast",
    "compose-up",
    "compose-down",
    "compose-ps",
    "compose-logs",
}


def _safe_path(rel_path: str) -> Path:
    p = (REPO_ROOT / rel_path).resolve()
    if not str(p).startswith(str(REPO_ROOT.resolve())):
        raise ValueError("Path escapes repo root")
    return p


def _run(cmd: list[str], timeout: int = 120) -> str:
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = []
    out.append(f"$ {' '.join(shlex.quote(x) for x in cmd)}")
    out.append(f"exit_code={proc.returncode}")
    if proc.stdout.strip():
        out.append("\nSTDOUT:\n" + proc.stdout.strip())
    if proc.stderr.strip():
        out.append("\nSTDERR:\n" + proc.stderr.strip())
    return "\n".join(out)


@mcp.tool()
def run_target(name: str) -> str:
    """Run one approved Make target."""
    if name not in ALLOWED_TARGETS:
        raise ValueError(
            f"Target '{name}' is not allowed. Allowed: {sorted(ALLOWED_TARGETS)}"
        )
    return _run(["make", name], timeout=300)


@mcp.tool()
def compose_ps() -> str:
    """Show docker compose service status."""
    return _run(["make", "compose-ps"], timeout=120)


@mcp.tool()
def compose_logs(service: str = "", tail: int = 200) -> str:
    """Show docker compose logs, optionally for one service."""
    cmd = ["docker", "compose", "logs", "--tail", str(max(1, min(tail, 500)))]
    if service:
        if not all(c.isalnum() or c in "-_." for c in service):
            raise ValueError("Invalid service name")
        cmd.append(service)
    return _run(cmd, timeout=180)


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file inside the repo root."""
    p = _safe_path(path)
    if not p.is_file():
        raise ValueError(f"Not a file: {path}")
    return p.read_text(encoding="utf-8")[:20000]


@mcp.tool()
def grep_code(query: str, glob: str = "**/*") -> str:
    """Search code with ripgrep inside the repo."""
    if not query.strip():
        raise ValueError("query is required")
    return _run(["rg", "-n", "--hidden", "--glob", glob, query, "."], timeout=120)


@mcp.tool()
def git_diff_summary() -> str:
    """Show git status and diff summary."""
    status = _run(["git", "status", "--short"], timeout=60)
    diff = _run(["git", "diff", "--stat"], timeout=60)
    return status + "\n\n" + diff


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
