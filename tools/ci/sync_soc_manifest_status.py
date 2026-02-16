# tools/ci/sync_soc_manifest_status.py
"""
2026-02-16: SOC manifest status sync tool

Purpose:
- Keep SOC finding statuses deterministic and CI-verifiable.
- Verify findings against their declared gate outcomes.
- Optionally write back updates (mark mitigated when a gate passes).

Modes:
- verify: do NOT write; fail if strict conditions are violated.
- sync:   write back mitigations; still fail on strict conditions if requested.

Targets:
- soc-manifest-verify: verify mode + --fail-on-unresolved-p0
- soc-manifest-sync:   sync mode + --write

Validation (expected):
- make soc-invariants
- make security-regression-gates
- make soc-manifest-verify
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "tools/ci/soc_findings_manifest.json"

NON_FINAL = {"open", "todo", "partial", "unknown"}
FINAL = {"mitigated", "waived"}

DEFAULT_GATE_TIMEOUT_S = 120  # keep short: these are CI gates, not a novel.
DEFAULT_GATE_OUTPUT_TAIL = 2000


@dataclass(frozen=True)
class GateResult:
    gate: str
    ok: bool
    rc: int
    output: str
    timed_out: bool = False


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise SystemExit(f"❌ manifest missing: {path}") from e
    except json.JSONDecodeError as e:
        raise SystemExit(f"❌ invalid JSON in manifest: {path} ({e})") from e


def _write_json_atomic(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _tail(s: str, n: int) -> str:
    if n <= 0:
        return ""
    return s if len(s) <= n else s[-n:]


def _run_gate(
    gate: str,
    timeout_s: int,
    env: Mapping[str, str],
    output_tail: int,
) -> GateResult:
    # Keep this predictable: no interactive output, no prompts.
    try:
        proc = subprocess.run(
            ["make", gate],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_s,
            env=env,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return GateResult(
            gate=gate,
            ok=(proc.returncode == 0),
            rc=proc.returncode,
            output=_tail(out.strip(), output_tail),
            timed_out=False,
        )
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or "") + (e.stderr or "")).strip()
        return GateResult(
            gate=gate,
            ok=False,
            rc=124,
            output=_tail(out, output_tail),
            timed_out=True,
        )


def _evidence_missing(evidence: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for rel in evidence:
        # treat non-str as invalid evidence entry
        if not isinstance(rel, str) or not rel.strip():
            missing.append(str(rel))
            continue
        if not (REPO / rel).exists():
            missing.append(rel)
    return missing


def _normalize_findings(
    data: Any,
) -> tuple[MutableMapping[str, Any], list[MutableMapping[str, Any]]]:
    """
    Returns:
      - root object (dict) to write back into (even if manifest is list, we wrap)
      - findings list as mutable dicts
    """
    if isinstance(data, dict):
        findings = data.get("findings", None)
        if findings is None:
            # Allow dict manifest where dict itself is a single finding list? No. Be strict.
            raise SystemExit("❌ manifest dict missing 'findings' key")
        if not isinstance(findings, list):
            raise SystemExit("❌ manifest 'findings' must be a list")
        if not all(isinstance(x, dict) for x in findings):
            raise SystemExit("❌ manifest 'findings' must contain objects")
        return data, findings  # type: ignore[return-value]
    if isinstance(data, list):
        if not all(isinstance(x, dict) for x in data):
            raise SystemExit("❌ manifest list must contain objects")
        # wrap to allow atomic writes without changing structure too much
        root = {"findings": data}
        return root, root["findings"]  # type: ignore[return-value]
    raise SystemExit(
        "❌ manifest must be a JSON object with 'findings' or a list of findings"
    )


def _validate_finding_shape(f: Mapping[str, Any]) -> list[str]:
    errs: list[str] = []
    if not f.get("id"):
        errs.append("missing id")
    if not f.get("severity"):
        errs.append("missing severity")
    if f.get("status") is None:
        errs.append("missing status")
    # gate can be absent for waived/finalized, but for non-final we require it
    return errs


def _make_env() -> dict[str, str]:
    # Keep env controlled; inherit but disable interactive stuff.
    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("PYTHONHASHSEED", "0")
    env.setdefault("TZ", "UTC")
    # Don't let random locale differences mess with output.
    env.setdefault("LC_ALL", "C")
    env.setdefault("LANG", "C")
    return env


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="sync_soc_manifest_status.py",
        description="Verify/sync SOC findings manifest statuses based on gate outcomes.",
    )
    p.add_argument(
        "--manifest",
        default=str(MANIFEST),
        help="Path to soc_findings_manifest.json (default: repo tools/ci/soc_findings_manifest.json).",
    )
    p.add_argument(
        "--mode",
        choices=["verify", "sync"],
        default="verify",
        help="verify=do not write; sync=write back mitigations (requires --write to persist).",
    )
    p.add_argument(
        "--write",
        action="store_true",
        help="Persist updates to the manifest (only meaningful in --mode sync).",
    )
    p.add_argument(
        "--fail-on-unresolved-p0",
        action="store_true",
        help="Fail if any P0 is still non-final after verification.",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_GATE_TIMEOUT_S,
        help=f"Per-gate timeout in seconds (default: {DEFAULT_GATE_TIMEOUT_S}).",
    )
    p.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="Parallel gate runs (default: 4). Use 1 for strict serialization.",
    )
    p.add_argument(
        "--output-tail",
        type=int,
        default=DEFAULT_GATE_OUTPUT_TAIL,
        help=f"Max gate output to retain for diagnostics (default: {DEFAULT_GATE_OUTPUT_TAIL}).",
    )
    args = p.parse_args(argv)

    manifest_path = Path(args.manifest).resolve()
    data_raw = _read_json(manifest_path)
    root, findings = _normalize_findings(data_raw)

    # Pre-validate all findings: fail fast on broken manifest
    shape_failures: list[str] = []
    for f in findings:
        errs = _validate_finding_shape(f)
        if errs:
            fid = f.get("id", "<missing-id>")
            shape_failures.append(f"{fid}: {', '.join(errs)}")
    if shape_failures:
        print("SOC manifest: INVALID")
        for e in shape_failures:
            print(" -", e)
        return 2

    mode = args.mode
    write = bool(args.write and mode == "sync")
    env = _make_env()

    # Build worklist for non-final findings only
    work: list[MutableMapping[str, Any]] = []
    for f in findings:
        status = str(f.get("status")).lower()
        if status in FINAL:
            continue
        work.append(f)

    # Validate evidence + gate presence first, before running any gates
    failures: list[str] = []
    gate_to_findings: dict[str, list[MutableMapping[str, Any]]] = {}

    for f in work:
        fid = f.get("id")
        status = f.get("status")
        gate = f.get("gate")
        evidence = f.get("evidence", [])

        if not isinstance(evidence, list):
            failures.append(f"{fid}: evidence must be a list")
            continue

        missing = _evidence_missing(evidence)
        if missing:
            failures.append(f"{fid}: missing evidence: {missing}")
            continue

        if not gate or not isinstance(gate, str):
            failures.append(
                f"{fid}: has no gate field (cannot verify non-final status={status})"
            )
            continue

        gate_to_findings.setdefault(gate, []).append(f)

        # If strict P0 enforcement is on, we still run the gate, but we’ll fail later if unresolved.

    # If any manifest structural failures exist, bail early
    if failures:
        print(f"SOC manifest {mode}: FAILED (preflight)")
        for x in failures:
            print(" -", x)
        return 1

    # Run each gate once, fan out results to all findings that reference it.
    gates = sorted(gate_to_findings.keys())
    results: dict[str, GateResult] = {}

    # If jobs <= 1, serialize for deterministic logs
    if args.jobs <= 1 or len(gates) <= 1:
        for g in gates:
            results[g] = _run_gate(g, args.timeout, env, args.output_tail)
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {
                ex.submit(_run_gate, g, args.timeout, env, args.output_tail): g
                for g in gates
            }
            for fut in as_completed(futs):
                g = futs[fut]
                try:
                    results[g] = fut.result()
                except Exception as e:  # truly unexpected
                    results[g] = GateResult(
                        gate=g, ok=False, rc=1, output=str(e), timed_out=False
                    )

    updated = 0
    gate_failures: list[str] = []

    # Apply results
    for gate, group in gate_to_findings.items():
        r = results[gate]
        if r.ok:
            for f in group:
                # Only flip to mitigated if it wasn't already final
                prev = str(f.get("status")).lower()
                if prev not in FINAL:
                    f["status"] = "mitigated"
                    updated += 1
        else:
            # Gate failed: record once, then unresolved findings handled below
            why = "timeout" if r.timed_out else f"rc={r.rc}"
            gate_failures.append(f"{gate} failed ({why})")

    # Strict unresolved P0 enforcement
    if args.fail_on_unresolved_p0:
        for f in findings:
            if f.get("severity") == "P0" and str(f.get("status")).lower() in NON_FINAL:
                gate = f.get("gate")
                failures.append(
                    f"{f.get('id')} is P0 but status={f.get('status')} (gate={gate})"
                )

    # If any gate failures and strict mode is verify, also fail (you asked for production grade)
    # In sync mode, still fail because "sync succeeded" while gates failed is nonsense.
    if gate_failures:
        failures.extend(gate_failures)

    # Only write if requested and changes exist
    if write and updated:
        # Preserve original manifest structure when possible:
        # - if original was dict with findings, write dict
        # - if original was list, write list (not wrapper)
        if isinstance(data_raw, list):
            _write_json_atomic(manifest_path, root["findings"])
        else:
            _write_json_atomic(manifest_path, root)

    if failures:
        print(f"SOC manifest {mode}: FAILED")
        for x in failures:
            print(" -", x)

        # Diagnostic tail for gates that failed
        for gate, r in results.items():
            if not r.ok:
                print()
                print(f"== gate: {gate} ==")
                if r.output:
                    print(r.output)
                else:
                    print("(no output captured)")
        return 1

    print(
        f"SOC manifest {mode}: OK (updated={updated}, write={write}, gates={len(gates)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
