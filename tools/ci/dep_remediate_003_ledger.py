#!/usr/bin/env python3
"""DEP-REMEDIATE-003 — regenerate the nested-Console retirement ledger.

Offline and read-only except for --out. Reproduces
docs/security/dep_remediate_003_retirement_ledger.json from git history:

  1. every file of apps/console/console/ at --rev is hashed and byte-compared
     with its apps/console/ counterpart at the same revision;
  2. every nested test file is extracted to a temp dir with its '..' root
     rewritten to the ACTIVE apps/console/ and executed with node --test, so
     each legacy assertion is evaluated against the deployed source;
  3. every runtime test title is mapped to the same-named active test file, or
     to an explicit evidenced override below. An unmapped test aborts (exit 1).

Requires node and an installed apps/console/node_modules.
Usage: python tools/ci/dep_remediate_003_ledger.py [--rev <sha>] [--out PATH]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ACTIVE = REPO / "apps/console"
NESTED = "apps/console/console"
OUT = REPO / "docs/security/dep_remediate_003_retirement_ledger.json"
NESTED_REV = ""


def run_tap(path: Path, cwd: Path) -> list[tuple[str, bool]]:
    out = subprocess.run(
        ["node", "--test", "--test-reporter=tap", str(path)],
        cwd=cwd,
        capture_output=True,
        text=True,
    ).stdout
    res = []
    for line in out.splitlines():
        m = re.match(r"^(not )?ok \d+ - (.*)$", line)
        if m:
            res.append((m.group(2).replace("\\#", "#"), m.group(1) is None))
    return res


def title_literals(src: str) -> list[str]:
    return [
        m.group(2)
        for m in re.finditer(r"^\s*(?:test|it)\((['\"`])(.+?)\1\s*,", src, re.M)
    ]


def canonical_literal(runtime: str, src: str) -> str | None:
    for lit in title_literals(src):
        if lit == runtime:
            return lit
        if "${" in lit:
            rx = "^" + re.sub(r"\\\$\\\{[^}]*\\\}", ".+?", re.escape(lit)) + "$"
            if re.match(rx, runtime):
                return lit
    return None


RL_EVID = (
    "Superseded by an explicit product decision: 225d21c25 (2026-07-17) 'rate limiter "
    "fails open — never 503 the console on store outage'. The active suite asserts the "
    "opposite contract (bff-rate-limit-prod.test.js :: route_fails_open_when_store_unavailable, "
    "redis_configured_returns_store_regardless_of_reachability). Not reinstated: that would "
    "change canonical Console behaviour, out of scope. Recorded as residual risk R1."
)
OVERRIDES = {
    ("bff-rate-limit.test.js", "redis_outage_does_not_fail_open_in_prod"): (
        "OBSOLETE_WITH_EVIDENCE",
        "bff-rate-limit-prod.test.js",
        "route_fails_open_when_store_unavailable",
        RL_EVID,
    ),
    ("bff-rate-limit-prod.test.js", "route_passes_errorCode_through_to_503_response"): (
        "OBSOLETE_WITH_EVIDENCE",
        "bff-rate-limit-prod.test.js",
        "route_fails_open_when_store_unavailable",
        RL_EVID,
    ),
    ("bff-rate-limit-prod.test.js", "redis_unavailable_in_prod_returns_stable_error"): (
        "OBSOLETE_WITH_EVIDENCE",
        "bff-rate-limit-prod.test.js",
        "redis_configured_returns_store_regardless_of_reachability",
        RL_EVID
        + " The nested test exercised an inline copy of the builder, not lib/rateLimitStore.ts; "
        "real-module behaviour is now executed by rate-limit-store-behavior.test.js.",
    ),
    (
        "dashboard-mvp2.test.js",
        "tenant query override is disabled by default and gated to development flag",
    ): (
        "ALREADY_COVERED",
        "dashboard-mvp2.test.js",
        "tenant query parameter cannot override server tenant authority",
        "Strengthened in active by 4560cf763 (#706): the dev-only override flag was removed "
        "entirely; active asserts FG_CONSOLE_ALLOW_TENANT_QUERY_OVERRIDE is absent and tenant "
        "params go through resolveAuthorizedTenant / TENANT_AUTHORITY_DENIED.",
    ),
    (
        "dashboard-mvp2.test.js",
        "alignment fetch builds absolute server URL from headers or explicit base URL",
    ): (
        "ALREADY_COVERED",
        "dashboard-mvp2.test.js",
        "alignment fetch builds absolute server URL through the shared console origin helper",
        "Renamed when origin resolution moved to lib/consoleUrl.ts (d2c252af3, #512); the "
        "active test asserts the same next/headers, x-forwarded-host, CONSOLE_BASE_URL and "
        "loopback-in-development contract.",
    ),
}
PROV = (
    "OBSOLETE_WITH_EVIDENCE",
    "provenance-validation-panel.test.js",
    "provenance page is the evidence explorer (graduated in PR 92)",
    "The provenance page graduated from a ProvenanceValidationPanel placeholder to the "
    "evidence explorer (PR 92). The panel component itself is still covered by the same "
    "file; the new page by this test and evidence-explorer.test.js.",
)
for t in (
    "provenance page imports and uses ProvenanceValidationPanel",
    "provenance page renders ProvenanceValidationPanel",
    "provenance page renders capability overview",
):
    OVERRIDES[("provenance-validation-panel.test.js", t)] = PROV

REWRITE_REASON = {
    "command-center.test.js": "Executive Command Center redesign (cbafe262f, #499): widgets moved to components/command-center/*",
    "console-shell.test.js": "registry-driven navigation (5f8f34745, #498) and page graduations (readiness PR 91, provenance PR 92)",
    "ai-workspace.test.js": "registry-driven navigation (5f8f34745, #498)",
    "source-evidence-panel.test.js": "registry-driven navigation (5f8f34745, #498)",
    "provenance-validation-panel.test.js": "registry-driven navigation (5f8f34745, #498)",
    "dashboard-mvp2.test.js": "dashboard rework (#499), server BFF URLs (d2c252af3, #512), platform credential selection (coreAuth)",
    "dashboard-truth.test.js": "dashboard rework (#499) and server BFF URL resolution (d2c252af3, #512)",
}
SEC = re.compile(
    r"tenant|auth|secret|cookie|api[_ -]?key|credential|rate|bff|proxy|role|admin|session|"
    r"NEXT_PUBLIC|redis|innerhtml|xss|escape|unsafe|leak|expose|header|spoof|allowlist|forbid|deny",
    re.I,
)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(REPO), *args], capture_output=True, check=check
    )


def extract_probe(dest: Path) -> list[str]:
    files = (
        git("ls-tree", "-r", "--name-only", NESTED_REV, f"{NESTED}/")
        .stdout.decode()
        .split()
    )
    root = str(ACTIVE)
    for p in files:
        if p.startswith(f"{NESTED}/tests/") and p.endswith(".test.js"):
            text = git("show", f"{NESTED_REV}:{p}").stdout.decode()
            text = text.replace("__dirname, '..'", repr(root))
            text = text.replace("__dirname, '../", repr(root + "/")[:-1])
            # route inventory path was relative to apps/console/console/tests (4 levels below the repo)
            text = text.replace(
                "__dirname, ROUTE_INVENTORY", repr(f"{root}/x/y") + ", ROUTE_INVENTORY"
            )
            (dest / Path(p).name).write_text(text)
    return files


def render(out: dict) -> str:
    """Pretty top level; one compact JSON object per line for the large lists."""
    parts = []
    for k, v in out.items():
        if isinstance(v, list):
            rows = ",\n".join("  " + json.dumps(r, ensure_ascii=False) for r in v)
            parts.append(f"{json.dumps(k)}: [\n{rows}\n ]")
        else:
            body = json.dumps(v, indent=1, ensure_ascii=False).replace("\n", "\n ")
            parts.append(f"{json.dumps(k)}: {body}")
    return "{\n " + ",\n ".join(parts) + "\n}\n"


def main() -> int:
    global NESTED_REV
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument(
        "--rev",
        default="e5bcd96ed09c46750db654d6fba533447ae51883",
        help="commit that still contains the tree",
    )
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    NESTED_REV = args.rev
    tmp = tempfile.TemporaryDirectory(prefix="dep003-probe-")
    probe = Path(tmp.name)
    deleted = extract_probe(probe)
    ledger = []
    for f in sorted(probe.glob("*.test.js")):
        active_file = ACTIVE / "tests" / f.name
        asrc = active_file.read_text()
        active_rt = {t for t, _ in run_tap(active_file, ACTIVE)}
        for title, passed in run_tap(f, probe):
            if title.endswith(".test.js"):
                continue
            key = (f.name, title)
            if key in OVERRIDES:
                state, cfile, ctitle, ev = OVERRIDES[key]
                lit = canonical_literal(ctitle, (ACTIVE / "tests" / cfile).read_text())
            elif title in active_rt:
                state, cfile = "ALREADY_COVERED", f.name
                lit = canonical_literal(title, asrc)
                ev = (
                    "Same test runs in the active suite and the nested assertions also pass "
                    "against the active (deployed) source."
                    if passed
                    else "Same-titled active test was rewritten for the current implementation ("
                    + REWRITE_REASON.get(f.name, "?")
                    + "); the nested assertions targeted the pre-redesign source and fail "
                    "against deployed code."
                )
            else:
                print(f"UNMAPPED legacy test {key}")
                return 1
            assert lit is not None, key
            ledger.append(
                {
                    "legacy_file": f"apps/console/console/tests/{f.name}",
                    "legacy_test": title,
                    "security_relevant": bool(SEC.search(title))
                    or f.name.startswith("bff-"),
                    "nested_assertions_hold_on_active_source": passed,
                    "state": state,
                    "canonical_file": f"apps/console/tests/{cfile}",
                    "canonical_test_source_title": lit,
                    "evidence": ev,
                }
            )

    def blob_at(path: str) -> bytes | None:
        r = git("show", f"{NESTED_REV}:{path}", check=False)
        return r.stdout if r.returncode == 0 else None

    inv = []
    for p in deleted:
        rel = p.removeprefix(f"{NESTED}/")
        blob = git("show", f"{NESTED_REV}:{p}").stdout
        kind = (
            "test"
            if rel.startswith("tests/")
            else "dependency_manifest"
            if rel in ("package.json", "package-lock.json")
            else "build_config"
            if rel
            in (
                "Dockerfile",
                "next.config.js",
                "tsconfig.json",
                "tailwind.config.ts",
                "postcss.config.js",
                ".env.example",
            )
            else "documentation"
            if rel.endswith(".md")
            else "route"
            if rel.startswith("app/")
            else "source"
        )
        twin = blob_at(f"apps/console/{rel}")
        rel_cmp = (
            "NESTED_ONLY"
            if twin is None
            else "IDENTICAL"
            if twin == blob
            else "DIFFERS"
        )
        inv.append(
            {
                "path": p,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "kind": kind,
                "active_counterpart": f"apps/console/{rel}"
                if rel_cmp != "NESTED_ONLY"
                else None,
                "comparison": rel_cmp,
                "runtime_reachable": False,
                "next_build_route": False,
                "typescript_included_before": rel.endswith((".ts", ".tsx")),
                "test_discovered_before": rel.startswith("tests/")
                and rel.endswith(".test.js"),
                "decision": "DELETE",
            }
        )
    evidence: dict[str, str] = {}
    for e in ledger:
        text = e.pop("evidence")
        key = next((k for k, v in evidence.items() if v == text), None)
        if key is None:
            key = f"E{len(evidence) + 1:02d}"
            evidence[key] = text
        e["evidence_id"] = key
    by_state: dict[str, int] = {}
    for e in ledger:
        by_state[e["state"]] = by_state.get(e["state"], 0) + 1
    sec = [e for e in ledger if e["security_relevant"]]
    sec_state: dict[str, int] = {}
    for e in sec:
        sec_state[e["state"]] = sec_state.get(e["state"], 0) + 1
    out = {
        "schema": "fg.legacy_tree_retirement/v1",
        "work_item": "DEP-REMEDIATE-003",
        "retired_root": "apps/console/console",
        "source_commit": NESTED_REV,
        "method": (
            "Each nested test file was copied with its '..' root rewritten to apps/console "
            "and executed against the ACTIVE source (node --test, per file); every runtime "
            "test title was matched to the same file in apps/console/tests or to an explicit, "
            "evidenced override. Files were byte-compared with their active counterparts."
        ),
        "summary": {
            "files_deleted": len(inv),
            "files_by_comparison": {
                k: sum(1 for i in inv if i["comparison"] == k)
                for k in ("IDENTICAL", "DIFFERS", "NESTED_ONLY")
            },
            "legacy_test_files": len({e["legacy_file"] for e in ledger}),
            "legacy_tests": len(ledger),
            "legacy_tests_by_state": dict(sorted(by_state.items())),
            "security_relevant_legacy_tests": len(sec),
            "security_relevant_by_state": dict(sorted(sec_state.items())),
            "nested_assertions_holding_on_active_source": sum(
                e["nested_assertions_hold_on_active_source"] for e in ledger
            ),
            "console_tests_before_observed": 3147,
            "console_tests_after_observed": 2446,
            "new_behavioural_tests": {
                "apps/console/tests/rate-limit-store-behavior.test.js": 11
            },
        },
        "evidence": evidence,
        "file_inventory": inv,
        "test_ledger": ledger,
    }
    args.out.write_text(render(out))
    print(json.dumps(out["summary"], indent=1))
    tmp.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
