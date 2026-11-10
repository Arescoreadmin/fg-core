#!/usr/bin/env python3
"""L14-FRONTEND-DEPENDENCY-SEC-001 — frontend dependency audit + SBOM gate.

Audits the npm lockfiles of the governed frontend applications and fails
closed:

* exit 0 — every app audited and no blocking advisory remains;
* exit 1 — at least one blocking advisory (critical or high, in either the
  production or the full lockfile tree) without an APPROVED, unexpired
  exception;
* exit 2 — AUDIT_UNVERIFIED: an audit could not run or produced output that
  is not a well-formed npm audit report.  Never reported as clean.

Evidence is bound to the source commit SHA and the exact lockfile hash and is
written as machine-readable JSON plus a Markdown summary (also appended to
``$GITHUB_STEP_SUMMARY`` when set).  Captured tool output is redacted of
registry tokens and URL credentials before it is persisted.

``sbom`` generates a CycloneDX SBOM per app with npm's built-in generator,
binds it to the same source SHA / lockfile hash, and validates its structure.

The decision logic (``extract_findings``, ``evaluate_app``,
``validate_exceptions``, ``validate_sbom``) is pure so it is exercised by
synthetic tests in ``tests/tools/test_frontend_dependency_audit.py``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
APPS: dict[str, str] = {
    "portal": "apps/portal",
    "console": "apps/console",
    "web": "apps/web",
}
EXCEPTIONS_PATH = REPO / "tools/ci/frontend_dependency_exceptions.json"
DEFAULT_OUT = REPO / "artifacts/frontend-dependency-security"
MAX_EXCEPTION_DAYS = 90
AUDIT_TIMEOUT_S = 300

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_UNVERIFIED = "AUDIT_UNVERIFIED"

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(_authToken\s*=\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(_auth\s*=\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
)


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_sha() -> str:
    env_sha = os.getenv("GITHUB_SHA", "").strip()
    if env_sha:
        return env_sha
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"


def _tool_version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or "UNKNOWN"
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"


# ---------------------------------------------------------------------------
# Pure decision logic
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    advisory_id: str
    url: str
    package: str
    severity: str
    vulnerable_range: str
    title: str
    paths: tuple[str, ...]
    fix_available: Any
    is_direct: bool


@dataclass
class AuditRun:
    """One ``npm audit`` invocation; ``error`` set means the run is unusable."""

    scope: str  # "production" | "all"
    returncode: int | None
    report: dict[str, Any] | None
    error: str | None = None


@dataclass
class AppResult:
    app: str
    status: str
    blocking: list[dict[str, Any]] = field(default_factory=list)
    excepted: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


def parse_audit_output(
    scope: str, returncode: int | None, stdout: str, stderr: str
) -> AuditRun:
    """Turn raw npm audit output into an ``AuditRun``; never guess "clean".

    npm exits 1 when vulnerabilities exist, so the exit code alone cannot
    distinguish findings from failure — the report shape decides.
    """
    if returncode is None:
        return AuditRun(scope, None, None, "npm audit did not complete (timeout)")
    try:
        report = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError:
        report = None
    if not isinstance(report, dict):
        detail = redact((stderr or stdout).strip())[:500]
        return AuditRun(
            scope, returncode, None, f"npm audit produced no JSON report: {detail}"
        )
    if "error" in report:
        err = report.get("error")
        err_detail = str(err.get("summary")) if isinstance(err, dict) else str(err)
        return AuditRun(
            scope, returncode, None, redact(f"npm audit error: {err_detail}")[:500]
        )
    meta = report.get("metadata", {}).get("vulnerabilities")
    if not isinstance(meta, dict) or not isinstance(
        report.get("vulnerabilities"), dict
    ):
        return AuditRun(
            scope, returncode, None, "npm audit report missing vulnerability metadata"
        )
    total = sum(int(v) for k, v in meta.items() if k != "total")
    if total == 0 and returncode not in (0,):
        return AuditRun(
            scope,
            returncode,
            None,
            f"npm audit exited {returncode} while reporting zero vulnerabilities",
        )
    if total > 0 and not report["vulnerabilities"]:
        return AuditRun(
            scope, returncode, None, "npm audit counts findings but lists none"
        )
    return AuditRun(scope, returncode, report)


def extract_findings(report: dict[str, Any]) -> list[Finding]:
    """One Finding per (advisory, package); paths preserved for evidence."""
    out: dict[tuple[str, str], Finding] = {}
    for pkg, vuln in sorted(report.get("vulnerabilities", {}).items()):
        for via in vuln.get("via", []):
            if not isinstance(via, dict):
                continue  # string entries are dependency-path edges
            adv_id = str(via.get("source", "")) or str(via.get("url", ""))
            url = str(via.get("url", ""))
            key = (adv_id or url, pkg)
            out[key] = Finding(
                advisory_id=adv_id,
                url=url,
                package=pkg,
                severity=str(via.get("severity", "unknown")).lower(),
                vulnerable_range=str(via.get("range", "")),
                title=str(via.get("title", "")),
                paths=tuple(vuln.get("nodes", [])),
                fix_available=vuln.get("fixAvailable"),
                is_direct=bool(vuln.get("isDirect", False)),
            )
    return sorted(out.values(), key=lambda f: (f.package, f.advisory_id))


def ghsa_of(url: str) -> str:
    m = re.search(r"(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})", url)
    return m.group(1) if m else ""


def validate_exceptions(
    raw: Any, today: dt.date
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return (usable_exceptions, problems).

    An exception is usable only when it is explicitly APPROVED by a named
    approver, names an owner, and has not expired (max 90-day horizon).
    Anything else is reported and ignored — i.e. the advisory still blocks.
    """
    problems: list[str] = []
    usable: list[dict[str, Any]] = []
    if not isinstance(raw, dict) or not isinstance(raw.get("exceptions"), list):
        return [], ["exception registry malformed: expected {'exceptions': [...]}"]
    required = (
        "id",
        "app",
        "package",
        "advisory",
        "owner",
        "expires",
        "approval_status",
        "approved_by",
        "runtime_exposure",
        "compensating_controls",
        "remediation_plan",
    )
    for exc in raw["exceptions"]:
        ident = exc.get("id", "<no id>") if isinstance(exc, dict) else "<invalid>"
        if not isinstance(exc, dict):
            problems.append(f"{ident}: not an object")
            continue
        missing = [k for k in required if not str(exc.get(k, "")).strip()]
        if missing:
            problems.append(f"{ident}: missing fields {missing}")
            continue
        if exc["approval_status"] != "APPROVED":
            problems.append(f"{ident}: approval_status={exc['approval_status']}")
            continue
        try:
            expires = dt.date.fromisoformat(str(exc["expires"]))
        except ValueError:
            problems.append(f"{ident}: invalid expires date")
            continue
        if expires < today:
            problems.append(f"{ident}: expired {expires.isoformat()}")
            continue
        if (expires - today).days > MAX_EXCEPTION_DAYS:
            problems.append(f"{ident}: expiry beyond {MAX_EXCEPTION_DAYS}-day horizon")
            continue
        usable.append(exc)
    return usable, problems


def _is_excepted(app: str, f: Finding, exceptions: list[dict[str, Any]]) -> bool:
    ids = {f.advisory_id, f.url, ghsa_of(f.url)} - {""}
    return any(
        e["app"] == app and e["package"] == f.package and str(e["advisory"]) in ids
        for e in exceptions
    )


def is_blocking(scope: str, severity: str) -> bool:
    """Critical/high block in BOTH audit scopes.

    The full-tree audit is not advisory: ``npm --omit=dev`` classification
    can drop production packages that are deduped with a devDependency (e.g.
    ``next``'s overridden ``postcss``), so high findings anywhere block.
    """
    del scope
    return severity in ("critical", "high")


def evaluate_app(
    app: str,
    runs: list[AuditRun],
    exceptions: list[dict[str, Any]],
) -> AppResult:
    result = AppResult(app=app, status=STATUS_PASS)
    for run in runs:
        if run.error or run.report is None:
            result.errors.append(f"{run.scope}: {run.error or 'no report'}")
            continue
        meta = run.report["metadata"]["vulnerabilities"]
        result.counts[run.scope] = {k: int(v) for k, v in meta.items()}
        findings = extract_findings(run.report)
        result.findings[run.scope] = [asdict(f) for f in findings]
        for f in findings:
            if not is_blocking(run.scope, f.severity):
                continue
            entry = {"scope": run.scope, **asdict(f)}
            if _is_excepted(app, f, exceptions):
                result.excepted.append(entry)
            else:
                result.blocking.append(entry)
    if len(result.counts) != len(runs) or result.errors:
        result.status = STATUS_UNVERIFIED
    elif result.blocking:
        result.status = STATUS_FAIL
    return result


def overall_status(results: list[AppResult]) -> str:
    if any(r.status == STATUS_UNVERIFIED for r in results):
        return STATUS_UNVERIFIED
    if any(r.status == STATUS_FAIL for r in results):
        return STATUS_FAIL
    return STATUS_PASS


def validate_sbom(bom: Any, *, expected_sha: str, expected_lock_sha: str) -> list[str]:
    """Structural CycloneDX validation + provenance binding checks."""
    errs: list[str] = []
    if not isinstance(bom, dict):
        return ["SBOM is not a JSON object"]
    if bom.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat is not CycloneDX")
    if str(bom.get("specVersion")) not in {"1.4", "1.5", "1.6"}:
        errs.append(f"unsupported specVersion {bom.get('specVersion')!r}")
    if not str(bom.get("serialNumber", "")).startswith("urn:uuid:"):
        errs.append("serialNumber missing or not urn:uuid")
    meta = bom.get("metadata") or {}
    if not meta.get("timestamp"):
        errs.append("metadata.timestamp missing")
    if not (meta.get("component") or {}).get("bom-ref"):
        errs.append("metadata.component (application identity) missing")
    if not meta.get("tools"):
        errs.append("metadata.tools (generator) missing")
    props = {p.get("name"): p.get("value") for p in meta.get("properties", [])}
    if props.get("fg:source_sha") != expected_sha:
        errs.append("fg:source_sha does not match source commit")
    if props.get("fg:lockfile_sha256") != expected_lock_sha:
        errs.append("fg:lockfile_sha256 does not match lockfile")
    comps = bom.get("components")
    if not isinstance(comps, list) or not comps:
        errs.append("components missing or empty")
        comps = []
    refs = {(meta.get("component") or {}).get("bom-ref")}
    for c in comps:
        if not (c.get("name") and c.get("version") and c.get("purl")):
            errs.append(f"component lacks name/version/purl: {c.get('bom-ref')}")
            break
        refs.add(c.get("bom-ref"))
    deps = bom.get("dependencies")
    if not isinstance(deps, list) or not deps:
        errs.append("dependencies (relationships) missing")
    else:
        for d in deps:
            unknown = [
                r for r in [d.get("ref"), *d.get("dependsOn", [])] if r not in refs
            ]
            if unknown:
                errs.append(f"dependency graph references unknown bom-ref {unknown[0]}")
                break
    return errs


# ---------------------------------------------------------------------------
# Side-effecting runners
# ---------------------------------------------------------------------------


def run_audit(app_dir: Path, scope: str) -> AuditRun:
    cmd = ["npm", "audit", "--json"]
    if scope == "production":
        cmd.append("--omit=dev")
    try:
        proc = subprocess.run(
            cmd, cwd=app_dir, capture_output=True, text=True, timeout=AUDIT_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        return parse_audit_output(scope, None, "", "")
    except OSError as exc:
        return AuditRun(scope, None, None, f"npm audit could not start: {exc}")
    return parse_audit_output(scope, proc.returncode, proc.stdout, proc.stderr)


def _evidence(app: str, app_dir: Path, sha: str) -> dict[str, Any]:
    lock = app_dir / "package-lock.json"
    return {
        "app": app,
        "path": APPS[app],
        "source_sha": sha,
        "lockfile": f"{APPS[app]}/package-lock.json",
        "lockfile_sha256": sha256_file(lock) if lock.exists() else None,
        "package_json_sha256": sha256_file(app_dir / "package.json"),
        "node_version": _tool_version(["node", "--version"]),
        "npm_version": _tool_version(["npm", "--version"]),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def _load_exceptions(today: dt.date) -> tuple[list[dict[str, Any]], list[str]]:
    if not EXCEPTIONS_PATH.exists():
        return [], [f"exception registry not found: {EXCEPTIONS_PATH.name}"]
    try:
        raw = json.loads(EXCEPTIONS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [], [f"exception registry invalid JSON: {exc}"]
    return validate_exceptions(raw, today)


def render_markdown(results: list[AppResult], status: str, sha: str) -> str:
    lines = [
        "## Frontend dependency security",
        "",
        f"Overall: **{status}** · source `{sha[:12]}`",
        "",
        "| App | Status | Prod crit/high | All crit/high/mod | Lockfile sha256 |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        p = r.counts.get("production", {})
        a = r.counts.get("all", {})
        lines.append(
            f"| {r.app} | {r.status} | {p.get('critical', '?')}/{p.get('high', '?')} "
            f"| {a.get('critical', '?')}/{a.get('high', '?')}/{a.get('moderate', '?')} "
            f"| `{str(r.evidence.get('lockfile_sha256'))[:16]}` |"
        )
    for r in results:
        for e in r.errors:
            lines.append(f"- **{r.app} AUDIT_UNVERIFIED:** {e}")
        for b in r.blocking:
            lines.append(
                f"- **{r.app} BLOCKING** {b['severity']} {b['package']} "
                f"{ghsa_of(b['url']) or b['advisory_id']} ({b['scope']}): {b['title']} "
                f"— paths: {', '.join(b['paths'])}"
            )
        for x in r.excepted:
            lines.append(
                f"- {r.app} excepted (approved, unexpired) {x['package']} "
                f"{ghsa_of(x['url']) or x['advisory_id']}"
            )
    return "\n".join(lines) + "\n"


def cmd_audit(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    today = dt.datetime.now(dt.timezone.utc).date()
    exceptions, exc_problems = _load_exceptions(today)
    sha = source_sha()
    results: list[AppResult] = []
    for app in args.apps:
        app_dir = REPO / APPS[app]
        if not (app_dir / "package-lock.json").exists():
            r = AppResult(
                app=app, status=STATUS_UNVERIFIED, errors=["lockfile missing"]
            )
        else:
            runs = [run_audit(app_dir, "production"), run_audit(app_dir, "all")]
            r = evaluate_app(app, runs, exceptions)
        r.evidence = _evidence(app, app_dir, sha)
        results.append(r)
        (out_dir / f"audit-{app}.json").write_text(
            redact(json.dumps(asdict(r), indent=2, sort_keys=True)) + "\n",
            encoding="utf-8",
        )
    status = overall_status(results)
    summary = {
        "gate": "L14-FRONTEND-DEPENDENCY-SEC-001",
        "status": status,
        "source_sha": sha,
        "policy": {
            "blocking": "critical + high in production and full-tree audits",
            "exceptions": "APPROVED, named approver, owner, unexpired, <=90 days",
            "unverified_is_failure": True,
        },
        "exception_registry_problems": exc_problems,
        "apps": {
            r.app: {
                "status": r.status,
                "blocking": len(r.blocking),
                "excepted": len(r.excepted),
                "counts": r.counts,
                "lockfile_sha256": r.evidence.get("lockfile_sha256"),
            }
            for r in results
        },
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    md = render_markdown(results, status, sha)
    if exc_problems:
        md += "\nException registry: " + "; ".join(exc_problems) + "\n"
    (out_dir / "summary.md").write_text(md, encoding="utf-8")
    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(md)
    print(md)
    return {STATUS_PASS: 0, STATUS_FAIL: 1}.get(status, 2)


def _purl(name: str, version: str) -> str:
    return f"pkg:npm/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{version}"


def _integrity_hash(integrity: str) -> list[dict[str, str]]:
    import base64

    out = []
    for part in (integrity or "").split():
        alg, _, b64 = part.partition("-")
        if alg in ("sha512", "sha384", "sha256", "sha1") and b64:
            try:
                digest = base64.b64decode(b64).hex()
            except ValueError:
                continue
            out.append({"alg": alg.upper().replace("SHA", "SHA-"), "content": digest})
    return out


def lockfile_to_cyclonedx(
    lock: dict[str, Any], *, app: str, generated_at: str, serial: str, tool: str
) -> dict[str, Any]:
    """CycloneDX 1.5 BOM from an npm v2/v3 lockfile (production tree only).

    The lockfile is what ``npm ci`` installs, so it is the authoritative
    inventory.  Dependency edges are resolved with Node's lookup rules over
    the lockfile's ``node_modules/`` paths (and ``link`` targets); a declared
    dependency that cannot be resolved is recorded, never silently dropped.
    """
    packages: dict[str, dict[str, Any]] = lock.get("packages") or {}
    if not packages:
        raise ValueError("lockfile has no 'packages' map (lockfileVersion < 2)")
    root = packages.get("", {})

    def target(path: str) -> str:
        meta = packages.get(path, {})
        return str(meta.get("resolved")) if meta.get("link") else path

    def resolve(from_path: str, dep: str) -> str | None:
        base = target(from_path)
        while True:
            cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if cand in packages:
                return cand
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            if idx >= 0:
                base = base[:idx]
            elif base.startswith("node_modules/"):
                base = ""
            else:
                # link target outside node_modules (e.g. ../../packages/ui):
                # Node resolves its bare imports through the app at bundle time.
                base = ""

    def name_of(path: str) -> str:
        meta = packages.get(path, {})
        if meta.get("name"):
            return str(meta["name"])
        return path.rsplit("node_modules/", 1)[-1]

    def ref_of(path: str) -> str:
        meta = packages.get(target(path), {})
        return f"{name_of(path)}@{meta.get('version', '0.0.0')}"

    root_ref = f"{root.get('name', app)}@{root.get('version', '0.0.0')}"
    included: dict[str, str] = {}  # path -> bom-ref
    edges: dict[str, set[str]] = {}
    unresolved: set[str] = set()
    queue: list[tuple[str, str]] = [("", root_ref)]
    seen: set[str] = set()
    while queue:
        path, ref = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        meta = packages.get(target(path), {})
        deps = dict(meta.get("dependencies") or {})
        deps.update(meta.get("optionalDependencies") or {})
        for pname in meta.get("peerDependencies") or {}:
            deps.setdefault(pname, "peer")
        edges.setdefault(ref, set())
        for dep in sorted(deps):
            resolved = resolve(path, dep)
            if resolved is None:
                if dep not in (meta.get("peerDependenciesMeta") or {}):
                    unresolved.add(f"{ref} -> {dep}")
                continue
            if packages.get(resolved, {}).get("dev"):
                continue
            dref = ref_of(resolved)
            edges[ref].add(dref)
            included[resolved] = dref
            queue.append((resolved, dref))

    components: dict[str, dict[str, Any]] = {}
    for path, ref in sorted(included.items()):
        meta = packages.get(target(path), {})
        link = bool(packages.get(path, {}).get("link"))
        comp: dict[str, Any] = {
            "bom-ref": ref,
            "type": "library",
            "name": name_of(path),
            "version": str(meta.get("version", "0.0.0")),
            "purl": _purl(name_of(path), str(meta.get("version", "0.0.0"))),
            "scope": "optional" if meta.get("optional") else "required",
            "properties": [{"name": "cdx:npm:package:path", "value": path}],
        }
        if link:
            comp["properties"].append(
                {"name": "fg:linked_source", "value": target(path)}
            )
        hashes = _integrity_hash(str(meta.get("integrity", "")))
        if hashes:
            comp["hashes"] = hashes
        if meta.get("resolved") and not link:
            comp["externalReferences"] = [
                {"type": "distribution", "url": str(meta["resolved"])}
            ]
        if meta.get("license"):
            comp["licenses"] = [{"expression": str(meta["license"])}]
        components.setdefault(ref, comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "lifecycles": [{"phase": "pre-build"}],
            "tools": [{"vendor": "FrostGate", "name": tool, "version": "1"}],
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": str(root.get("name", app)),
                "version": str(root.get("version", "0.0.0")),
            },
            "properties": [
                {"name": "fg:unresolved_dependency", "value": u}
                for u in sorted(unresolved)
            ],
        },
        "components": [components[k] for k in sorted(components)],
        "dependencies": [
            {"ref": r, "dependsOn": sorted(d)} for r, d in sorted(edges.items())
        ],
    }


def cmd_sbom(args: argparse.Namespace) -> int:
    import uuid

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    sha = source_sha()
    rc = 0
    npm_version = _tool_version(["npm", "--version"])
    manifest: dict[str, Any] = {"source_sha": sha, "sboms": {}}
    for app in args.apps:
        app_dir = REPO / APPS[app]
        lock_path = app_dir / "package-lock.json"
        try:
            lock_sha = sha256_file(lock_path)
            bom = lockfile_to_cyclonedx(
                json.loads(lock_path.read_text(encoding="utf-8")),
                app=app,
                generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                serial=f"urn:uuid:{uuid.uuid4()}",
                tool="frontend_dependency_audit.lockfile_to_cyclonedx",
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"[sbom] {app}: generation failed: {redact(str(exc))}")
            rc = 2
            continue
        bom["metadata"]["properties"].extend(
            [
                {"name": "fg:source_sha", "value": sha},
                {"name": "fg:app", "value": app},
                {"name": "fg:lockfile", "value": f"{APPS[app]}/package-lock.json"},
                {"name": "fg:lockfile_sha256", "value": lock_sha},
                {"name": "fg:scope", "value": "production (devDependencies omitted)"},
                {"name": "fg:npm_version", "value": npm_version},
                {"name": "fg:signed", "value": "false"},
            ]
        )
        errs = validate_sbom(bom, expected_sha=sha, expected_lock_sha=lock_sha)
        path = out_dir / f"sbom-{app}.cdx.json"
        path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
        manifest["sboms"][app] = {
            "file": path.name,
            "sha256": sha256_file(path),
            "components": len(bom.get("components", [])),
            "spec_version": bom.get("specVersion"),
            "lockfile_sha256": lock_sha,
            "valid": not errs,
            "errors": errs,
        }
        print(
            f"[sbom] {app}: {'VALID' if not errs else 'INVALID'} "
            f"components={len(bom.get('components', []))} sha256={manifest['sboms'][app]['sha256']}"
        )
        if errs:
            print("   " + "; ".join(errs))
            rc = 2
    (out_dir / "sbom-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("audit", "sbom"):
        p = sub.add_parser(name)
        p.add_argument("--app", dest="apps", action="append", choices=sorted(APPS))
        p.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)
    args.apps = args.apps or list(APPS)
    return cmd_audit(args) if args.cmd == "audit" else cmd_sbom(args)


if __name__ == "__main__":
    sys.exit(main())
