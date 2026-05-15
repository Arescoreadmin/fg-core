#!/usr/bin/env python3
"""
check_safe_telemetry.py — static analysis gate preventing leakage of sensitive
field names into metric labels, span attributes, and structured log extra= fields.

What it checks
--------------
1. Prometheus metric label name lists — Counter/Histogram/Gauge(..., ["label"]) literals
2. span.set_attribute(key, ...) calls — key string literal must not be a sensitive fragment
3. logger.*/logging.* extra={} dict literal keys — must not be sensitive fragments

Why this matters
----------------
The SecretRedactionFilter strips secrets at log-sink time, but:
- Metric labels are permanent and cannot be redacted post-emission.
- Span attributes are stored in the trace backend before any filter can run.
- A future contributor *will* accidentally pass raw_prompt or api_key as a
  label/attribute. This gate makes that impossible to merge.

Forbidden fragments (case-insensitive substring match on field names):
  raw_prompt, raw_chunk, provider_payload, authorization, api_key, apikey,
  api-key, _token (access_token/auth_token/bearer_token — not token_fingerprint),
  bearer, password, secret, credential, private_key, signing_key, x_api_key

Usage
-----
  python tools/ci/check_safe_telemetry.py [path ...]
  python tools/ci/check_safe_telemetry.py api/ tests/

Exit codes: 0 = clean, 1 = violations found.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

FORBIDDEN_FRAGMENTS: frozenset[str] = frozenset(
    {
        "raw_prompt",
        "raw_chunk",
        "provider_payload",
        "authorization",
        "api_key",
        "apikey",
        "api-key",
        "_token",  # access_token, auth_token, bearer_token, refresh_token — not token_fingerprint
        "bearer",
        "password",
        "secret",
        "credential",
        "private_key",
        "signing_key",
        "x_api_key",
    }
)

# Metric constructor function names recognised by this checker.
_METRIC_CONSTRUCTORS = {"Counter", "Histogram", "Gauge", "Summary", "Info", "Enum"}

# Logging call attributes (logger.info, logger.warning, logging.info, etc.)
_LOG_FUNC_NAMES = {
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "critical",
    "exception",
    "log",
}


def _is_forbidden(name: str) -> bool:
    low = name.lower()
    return any(frag in low for frag in FORBIDDEN_FRAGMENTS)


def _string_value(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _Checker(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.violations: list[str] = []

    def _violation(self, lineno: int, kind: str, field: str) -> None:
        self.violations.append(
            f"{self.path}:{lineno}: [{kind}] forbidden field name '{field}'"
        )

    # ------------------------------------------------------------------
    # Rule 1: metric label lists
    # Counter("name", "help", ["label1", "label2"])
    # Counter("name", "help", ["label1"], buckets=(...))
    # ------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        func_name: str | None = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in _METRIC_CONSTRUCTORS:
            for arg in node.args:
                if isinstance(arg, ast.List):
                    for elt in arg.elts:
                        val = _string_value(elt)
                        if val and _is_forbidden(val):
                            self._violation(
                                elt.lineno,
                                "metric_label",
                                val,
                            )
            for kw in node.keywords:
                if kw.arg == "labelnames" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        val = _string_value(elt)
                        if val and _is_forbidden(val):
                            self._violation(elt.lineno, "metric_label", val)

        # Rule 2: span.set_attribute(key, value)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "set_attribute"
            and node.args
        ):
            val = _string_value(node.args[0])
            if val and _is_forbidden(val):
                self._violation(node.args[0].lineno, "span_attribute", val)

        # Rule 3: logger.*(msg, extra={"key": ...}) or logging.*(msg, extra={...})
        if func_name in _LOG_FUNC_NAMES:
            for kw in node.keywords:
                if kw.arg == "extra" and isinstance(kw.value, ast.Dict):
                    for key_node in kw.value.keys:
                        if key_node is None:
                            continue
                        val = _string_value(key_node)
                        if val and _is_forbidden(val):
                            self._violation(key_node.lineno, "log_extra_key", val)

        self.generic_visit(node)


def check_file(path: Path) -> list[str]:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []
    checker = _Checker(path)
    checker.visit(tree)
    return checker.violations


def collect_python_files(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if root.is_file() and root.suffix == ".py":
            files.append(root)
        elif root.is_dir():
            files.extend(sorted(root.rglob("*.py")))
    return files


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    if args:
        roots = [Path(a) for a in args]
    else:
        repo_root = Path(__file__).resolve().parents[2]
        roots = [
            repo_root / "api",
            repo_root / "services",
            repo_root / "tests",
        ]

    all_violations: list[str] = []
    for f in collect_python_files(roots):
        all_violations.extend(check_file(f))

    if all_violations:
        print("safe-telemetry-check: FAILED")
        for v in sorted(all_violations):
            print(f"  {v}")
        return 1

    print("safe-telemetry-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
