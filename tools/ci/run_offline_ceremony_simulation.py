#!/usr/bin/env python3
"""Offline ceremony simulation runner.

Deterministic zero-cost simulation of Customer-Zero trust ceremony mechanics.
Uses ephemeral TEST-ONLY Ed25519 keys (never production Vault keys).

Produces a machine-readable evidence record at:
    customer_one/offline_simulation_evidence.json

This evidence is consumed by the J_CE3 dimension of
customer_zero_final_readiness.py. The simulation is NOT a substitute for a
paid ceremony. It validates that trust ceremony MECHANICS work correctly
without cloud infrastructure.

Checks executed:
    1. trust_keys_generated           — Ed25519 keys for all three trust roles
    2. identity_domain_sign_verify    — IDENTITY domain round-trip (report binding)
    3. approval_domain_sign_verify    — APPROVAL domain round-trip (qualification)
    4. acceptance_domain_sign_verify  — ACCEPTANCE domain round-trip (delivery auth)
    5. cross_domain_isolation         — IDENTITY sig rejected under APPROVAL role and vice versa
    6. verifier_contract_fail_closed  — Wrong key, tampered payload, wrong domain all -> False

SAFETY:
  - TEST-ONLY keys generated ephemerally; never persisted
  - FG_ENV must NOT be production or staging
  - No network calls, no cloud mutations, no paid infrastructure

Usage:
    python tools/ci/run_offline_ceremony_simulation.py
    python tools/ci/run_offline_ceremony_simulation.py --repo /path/to/fg-core
    python tools/ci/run_offline_ceremony_simulation.py --dry-run  # print result, do not write

EXIT CODES:
    0 — Simulation GREEN (all checks passed)
    1 — Simulation FAILED (one or more checks failed)
    2 — Internal error (import failure, environment rejected)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("FG_ENV", "test")

SCHEMA_VERSION = "1.0"
EVIDENCE_RELPATH = "customer_one/offline_simulation_evidence.json"
SIMULATION_CONTRACT_VERSION = "1.0"

_PRODUCTION_ENVIRONMENTS = {"production", "staging", "prod"}


def _reject_production() -> None:
    env = os.getenv("FG_ENV", "test").lower()
    if env in _PRODUCTION_ENVIRONMENTS:
        print(
            f"ERROR: Offline simulation runner must not be used in environment '{env}'",
            file=sys.stderr,
        )
        sys.exit(2)
    cz_env = os.getenv("FG_CUSTOMER_ZERO_ENVIRONMENT", "").lower()
    if cz_env in _PRODUCTION_ENVIRONMENTS:
        print(
            f"ERROR: Offline simulation runner must not be used in CZ environment '{cz_env}'",
            file=sys.stderr,
        )
        sys.exit(2)


def _git_head(repo: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _compute_tree_content_hash(repo: Path, exclude_relpath: str) -> str:
    """SHA-256 of tracked file contents excluding the evidence file itself.

    Uses 'git ls-files' so the evidence file, whether untracked (freshly
    written) or already committed, is consistently excluded from the hash.
    This means the hash is the same before and after committing the evidence
    file, breaking the HEAD-SHA chicken-and-egg.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return "TREE_HASH_ERROR"
        files = sorted(
            f for f in result.stdout.split("\0") if f and f != exclude_relpath
        )
        h = hashlib.sha256()
        for relpath in files:
            path = repo / relpath
            try:
                h.update(relpath.encode("utf-8"))
                h.update(b"\x00")
                h.update(path.read_bytes())
                h.update(b"\x00")
            except OSError:
                h.update(relpath.encode("utf-8"))
                h.update(b"\x00FILE_ABSENT\x00")
        return h.hexdigest()
    except Exception:
        return "TREE_HASH_ERROR"


def _run_simulation(repo: Path) -> dict:
    """Execute all simulation checks. Returns evidence dict."""
    from services.governance.trust_binding import (
        DOMAIN_DELIVERY_AUTHORIZATION,
        DOMAIN_QUALIFICATION,
        DOMAIN_REPORT,
        TrustBindingAuthority,
        build_delivery_authorization_signing_payload,
        build_qualification_signing_payload,
        build_report_signing_payload,
    )
    from services.governance.trust_binding_fake import TrustBindingFake
    from services.cgin.key_management.vault_transit import TrustRole

    checks_executed: list[str] = []
    checks_passed_names: list[str] = []
    checks_failed_names: list[str] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        checks_executed.append(name)
        if passed:
            checks_passed_names.append(name)
        else:
            checks_failed_names.append(name)
        status = "PASS" if passed else "FAIL"
        suffix = f" — {detail}" if detail else ""
        print(f"  [{status}] {name}{suffix}")

    print("Running offline ceremony simulation...")

    # ------------------------------------------------------------------ #
    # Check 1: trust_keys_generated                                       #
    # ------------------------------------------------------------------ #
    try:
        fake = TrustBindingFake()
        authority = TrustBindingAuthority(fake)
        # Verify all three roles have keys
        for role in TrustRole:
            pub_b64 = fake.public_key_b64(role)
            fp = fake.fingerprint(role)
            assert pub_b64 and len(pub_b64) > 0, f"No public key for {role}"
            assert fp and len(fp) > 0, f"No fingerprint for {role}"
        record(
            "trust_keys_generated", True, f"{len(list(TrustRole))} trust roles keyed"
        )
    except Exception as exc:
        record("trust_keys_generated", False, str(exc))

    # ------------------------------------------------------------------ #
    # Check 2: identity_domain_sign_verify (report binding)               #
    # ------------------------------------------------------------------ #
    try:
        report_payload = build_report_signing_payload(
            tenant_id="sim-tenant-001",
            engagement_id="sim-eng-001",
            report_id="sim-rep-001",
            report_version_id="sim-rv-001",
            report_fingerprint="a" * 64,
            report_schema_version="1.0",
        )
        envelope = authority.sign_report(report_payload)
        ok = authority.verify_report(report_payload, envelope)
        record("identity_domain_sign_verify", ok and envelope.domain == DOMAIN_REPORT)
    except Exception as exc:
        record("identity_domain_sign_verify", False, str(exc))

    # ------------------------------------------------------------------ #
    # Check 3: approval_domain_sign_verify (qualification)                #
    # ------------------------------------------------------------------ #
    try:
        qual_payload = build_qualification_signing_payload(
            tenant_id="sim-tenant-001",
            engagement_id="sim-eng-001",
            report_id="sim-rep-001",
            qual_request_id="sim-qr-001",
            report_version_id="sim-rv-001",
            report_fingerprint="b" * 64,
            decision="QUALIFIED",
            decided_by="sim-actor-001",
            schema_version="1.0",
        )
        qual_env = authority.sign_qualification(qual_payload)
        ok = authority.verify_qualification(qual_payload, qual_env)
        record(
            "approval_domain_sign_verify",
            ok and qual_env.domain == DOMAIN_QUALIFICATION,
        )
    except Exception as exc:
        record("approval_domain_sign_verify", False, str(exc))

    # ------------------------------------------------------------------ #
    # Check 4: acceptance_domain_sign_verify (delivery authorization)     #
    # ------------------------------------------------------------------ #
    try:
        da_payload = build_delivery_authorization_signing_payload(
            tenant_id="sim-tenant-001",
            engagement_id="sim-eng-001",
            report_id="sim-rep-001",
            report_version_id="sim-rv-001",
            report_fingerprint="c" * 64,
            qualification_decision_id="sim-qd-001",
            delivery_request_id="sim-dr-001",
            recipient_type="PORTAL",
            recipient_id=None,
            channel="portal",
            outcome="DELIVERED",
            schema_version="1.0",
        )
        da_env = authority.sign_delivery_authorization(da_payload)
        ok = authority.verify_delivery_authorization(da_payload, da_env)
        record(
            "acceptance_domain_sign_verify",
            ok and da_env.domain == DOMAIN_DELIVERY_AUTHORIZATION,
        )
    except Exception as exc:
        record("acceptance_domain_sign_verify", False, str(exc))

    # ------------------------------------------------------------------ #
    # Check 5: cross_domain_isolation                                     #
    # Verify that an IDENTITY signature is rejected under the APPROVAL    #
    # role key (and vice versa).                                          #
    # ------------------------------------------------------------------ #
    try:
        # Build a second authority with different keys
        fake2 = TrustBindingFake()
        authority2 = TrustBindingAuthority(fake2)

        # Sign with authority1/identity, verify with authority2/identity — must fail
        env_id = authority.sign_report(report_payload)
        cross_ok = authority2.verify_report(report_payload, env_id)  # must be False

        # Sign with authority1/approval, try to verify as identity — must fail
        env_qual = authority.sign_qualification(qual_payload)
        # Direct wrong-role check using the fake's wrong_role_verify
        from services.governance.trust_binding import _prepare_signing_bytes

        signing_bytes_report = _prepare_signing_bytes(
            env_qual.domain,
            {k: v for k, v in qual_payload.items() if k != "domain"},
        )
        wrong_role_ok = fake.wrong_role_verify(
            TrustRole.APPROVAL, signing_bytes_report, env_qual.signature
        )

        isolation_ok = (not cross_ok) and (not wrong_role_ok)
        record(
            "cross_domain_isolation",
            isolation_ok,
            "cross-authority rejected, wrong-role rejected",
        )
    except Exception as exc:
        record("cross_domain_isolation", False, str(exc))

    # ------------------------------------------------------------------ #
    # Check 6: verifier_contract_fail_closed                              #
    # Wrong key, tampered payload, and wrong domain all return False.     #
    # ------------------------------------------------------------------ #
    try:
        fail_closed_ok = True

        # 6a: wrong key (authority2 key against authority1 signature)
        env_r = authority.sign_report(report_payload)
        r1 = authority2.verify_report(report_payload, env_r)
        if r1 is not False:
            fail_closed_ok = False

        # 6b: tampered payload (modify a field)
        tampered = dict(report_payload)
        tampered["report_fingerprint"] = "z" * 64
        r2 = authority.verify_report(tampered, env_r)
        if r2 is not False:
            fail_closed_ok = False

        # 6c: wrong domain envelope (use qualification envelope to verify report)
        fake3 = TrustBindingFake()
        auth3 = TrustBindingAuthority(fake3)
        from services.governance.trust_binding import SignatureEnvelope

        env_q_signed = auth3.sign_qualification(qual_payload)
        # Construct a spoofed report envelope using the qualification signature
        spoofed = SignatureEnvelope(
            issuer=env_q_signed.issuer,
            trust_role=env_q_signed.trust_role,
            key_id=env_q_signed.key_id,
            key_version=env_q_signed.key_version,
            algorithm=env_q_signed.algorithm,
            public_key_fingerprint=env_q_signed.public_key_fingerprint,
            signature=env_q_signed.signature,
            domain=DOMAIN_REPORT,  # claim it's a report domain
            signed_payload_sha256=env_q_signed.signed_payload_sha256,
        )
        r3 = auth3.verify_report(report_payload, spoofed)
        if r3 is not False:
            fail_closed_ok = False

        record(
            "verifier_contract_fail_closed",
            fail_closed_ok,
            "wrong-key=False, tampered=False, wrong-domain=False",
        )
    except Exception as exc:
        record("verifier_contract_fail_closed", False, str(exc))

    source_sha = _git_head(
        repo
    )  # informational only — changes on every commit; use source_tree_hash for binding
    source_tree_hash = _compute_tree_content_hash(repo, EVIDENCE_RELPATH)
    result = "GREEN" if not checks_failed_names else "FAILED"

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "simulation_id": str(uuid.uuid4()),
        "source_sha": source_sha,
        "source_tree_hash": source_tree_hash,
        "simulation_contract_version": SIMULATION_CONTRACT_VERSION,
        "result": result,
        "checks_executed": checks_executed,
        "checks_passed": len(checks_passed_names),
        "checks_failed": len(checks_failed_names),
        "failed_checks": checks_failed_names,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "evidence_reference": EVIDENCE_RELPATH,
        "test_only": True,
        "paid_infrastructure_required": False,
    }
    return evidence


def main(argv: list[str] | None = None) -> int:
    _reject_production()

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--repo",
        default=str(_ROOT),
        help="Root of the FrostGate repository (default: auto-detected)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print result to stdout without writing the evidence file",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Override output path (default: <repo>/customer_one/offline_simulation_evidence.json)",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()

    print("=" * 60)
    print("OFFLINE CEREMONY SIMULATION")
    print("TEST-ONLY: ephemeral Ed25519 keys, no Vault, no cloud")
    print("=" * 60)

    try:
        evidence = _run_simulation(repo)
    except SystemExit:
        raise
    except Exception as exc:
        print(
            f"\nFATAL: simulation failed with unexpected error: {exc}", file=sys.stderr
        )
        return 2

    result = evidence.get("result", "FAILED")
    checks_passed = evidence.get("checks_passed", 0)
    checks_failed = evidence.get("checks_failed", 0)

    print()
    print(f"Result:         {result}")
    print(f"Checks passed:  {checks_passed}")
    print(f"Checks failed:  {checks_failed}")
    print(f"Source SHA:     {evidence.get('source_sha', 'unknown')}")
    print(f"Simulation ID:  {evidence.get('simulation_id', 'unknown')}")

    if args.dry_run:
        print("\n[dry-run] Evidence NOT written.")
        print(json.dumps(evidence, indent=2))
        return 0 if result == "GREEN" else 1

    output_path = Path(args.output) if args.output else repo / EVIDENCE_RELPATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    print(f"\nEvidence written: {output_path}")

    if result == "GREEN":
        print("SIMULATION GREEN — all checks passed.")
        return 0
    else:
        print("SIMULATION FAILED — one or more checks failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
