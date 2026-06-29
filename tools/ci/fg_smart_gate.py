from __future__ import annotations

import subprocess
from pathlib import Path

from tools.ci.context_registry import ContextRegistry

BASE_REF = "origin/main"


def run(cmd: list[str]) -> None:
    print("\n==>", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def output(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def changed_files() -> list[str]:
    try:
        raw = output(["git", "diff", "--name-only", f"{BASE_REF}...HEAD"])
    except subprocess.CalledProcessError:
        raw = output(["git", "diff", "--name-only"])
    return [line for line in raw.splitlines() if line.strip()]


def path_exists(test_path: str) -> bool:
    base = test_path.split("::", 1)[0]
    return Path(base).exists()


def _estimate_runtime_minutes(test_count: int, gate_count: int) -> int:
    return max(1, test_count // 3 + gate_count * 2)


def main() -> int:
    registry = ContextRegistry.load()
    files = changed_files()
    py_files = [f for f in files if f.endswith(".py") and Path(f).exists()]

    raw_contexts = registry.detect_contexts(files)
    expanded = registry.expand_dependencies(raw_contexts)
    added_deps = expanded - raw_contexts

    context_tests = registry.collect_tests(raw_contexts)
    conditional_gates = registry.collect_gates(files)
    always_cfg = registry.global_config

    print("=" * 52)
    print("FROSTGATE SMART VALIDATION")
    print("=" * 52)
    print(f"Registry Version      {registry.version}")
    print(f"Base ref              {BASE_REF}")

    print("\nChanged files:")
    if files:
        for f in files:
            print(f"  - {f}")
    else:
        print("  (none detected)")

    print("\nChanged Contexts:")
    if raw_contexts:
        for ctx in sorted(raw_contexts):
            print(f"  ✓ {ctx}")
    else:
        print("  (none — generic run)")

    if added_deps:
        print("\nExpanded Dependencies:")
        for dep in sorted(added_deps):
            print(f"  ✓ {dep}")

    # Build the full gate list for the summary
    gate_summary: list[str] = []
    for always_cmd in always_cfg.always_gates:
        gate_summary.append(" ".join(always_cmd))
    for cond_cmd in conditional_gates:
        gate_summary.append(" ".join(cond_cmd))

    print("\nValidation Plan:")
    for g in gate_summary:
        print(f"  {g}")
    if context_tests:
        print("  pytest (targeted)")
    else:
        print("  pytest (smoke)")

    unique_tests: list[str] = []
    seen: set[str] = set()
    for t in context_tests:
        if t not in seen and path_exists(t):
            unique_tests.append(t)
            seen.add(t)

    for t in always_cfg.always_tests:
        if t not in seen and path_exists(t):
            unique_tests.append(t)
            seen.add(t)

    if unique_tests:
        print("\nTargeted Tests:")
        for t in unique_tests:
            print(f"  {t}")

    est = _estimate_runtime_minutes(len(unique_tests), len(gate_summary))
    print(f"\nEstimated Runtime     ~{est} minute(s)")
    print("=" * 52)

    # ── Execute ────────────────────────────────────────────────────────────

    if py_files:
        run(["ruff", "check", *py_files])
        run(["ruff", "format", "--check", *py_files])
    else:
        print("\n==> No changed Python files for ruff")

    run(["mypy", "."])

    for always_gate_cmd in always_cfg.always_gates:
        run(list(always_gate_cmd))

    for cond_gate_cmd in conditional_gates:
        run(cond_gate_cmd)

    if unique_tests:
        run(["pytest", "-q", *unique_tests])
    else:
        print("\n==> No context tests detected; running smoke tests")
        run(["pytest", "-q", *list(always_cfg.always_tests)])

    print("\n" + "=" * 52)
    print("FrostGate Smart PR Gate: PASS")
    print("=" * 52)
    print(
        f"Contexts : {', '.join(sorted(raw_contexts)) if raw_contexts else 'generic'}"
    )
    print(f"Tests    : {len(unique_tests)} target(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
