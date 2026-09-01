#!/usr/bin/env python3
"""
PR-CORE-002 (#645) production proof matrix.

Usage:
    FG_GATEWAY_DELEGATION_SECRET_CURRENT=<secret> \
    ADMIN_GATEWAY_URL=https://... \
    FG_INTERNAL_GATEWAY_SECRET=<internal-gateway-secret> \
    PROOF_TENANT=<active-tenant-id> \
    INACTIVE_TENANT=<suspended-tenant-id> \
    python tools/testing/security/prod_proof_645.py

All six gates must report PASS for the production proof to be accepted.
Never pass secrets as positional args — use environment variables only.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time
import uuid

import requests

# ---------------------------------------------------------------------------
# Config from environment — never print values
# ---------------------------------------------------------------------------

SECRET = os.environ["FG_GATEWAY_DELEGATION_SECRET_CURRENT"]
GATEWAY_URL = os.environ["ADMIN_GATEWAY_URL"].rstrip("/")
# This proof exercises the BFF admin_internal_token path (Path B — Console→BFF→Core).
# On Path B, both X-API-Key and X-FG-Internal-Token carry the same FG_INTERNAL_GATEWAY_SECRET
# value. This is intentionally correct: the BFF emits the shared secret on both headers
# because AuthGateMiddleware checks X-API-Key for presence and require_internal_admin_gateway
# checks X-FG-Internal-Token for trust. The delegation proof then validates the X-FG-Delegation-*
# headers that the BFF attaches. Do NOT confuse this with the direct PSP path (Path A), where
# X-API-Key carries the fgk.* credential and X-FG-Internal-Token carries the gateway secret
# as separate distinct values.
INTERNAL_GATEWAY_SECRET = os.environ["FG_INTERNAL_GATEWAY_SECRET"]
TENANT = os.environ["PROOF_TENANT"]
INACTIVE = os.environ.get("INACTIVE_TENANT", "")

PROBE_PATH = f"/admin/identity/tenants/{TENANT}/config"
# BFF envelope contract — must match apps/console/app/api/core/[...path]/route.ts:
#   X-API-Key          → FG_INTERNAL_GATEWAY_SECRET (required for AuthGateMiddleware key check)
#   X-FG-Internal-Token → FG_INTERNAL_GATEWAY_SECRET (admin_internal_token resolution)
#   X-Admin-Gateway-Internal → "true" (marks request as internal admin gateway)
#   X-Tenant-ID        → resolved tenant (forwarded by BFF)
# Same value on both headers is correct for Path B (BFF emulation). See comment above.
ADMIN_HEADERS = {
    "X-API-Key": INTERNAL_GATEWAY_SECRET,
    "X-FG-Internal-Token": INTERNAL_GATEWAY_SECRET,
    "X-Admin-Gateway-Internal": "true",
    "X-Tenant-ID": TENANT,
}

RESULTS: list[tuple[str, bool, str]] = []


def _proof(secret: str, req_id: str, tenant: str, method: str, path: str) -> dict:
    iat = int(time.time())
    exp = iat + 60
    canonical = f"v1\n{req_id}\n{tenant}\n{method.upper()}\n{path}\n{iat}\n{exp}"
    digest = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return {
        "X-FG-Delegation-Version": "v1",
        "X-FG-Delegation-Issued-At": str(iat),
        "X-FG-Delegation-Expires-At": str(exp),
        "X-FG-Delegation-Proof": digest,
        "X-Request-ID": req_id,
    }


def _req(
    method: str, path: str, extra_headers: dict | None = None
) -> requests.Response:
    url = f"{GATEWAY_URL}{path}"
    headers = {**ADMIN_HEADERS, "Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return requests.request(method, url, headers=headers, timeout=15)


def gate(
    name: str, expect: int, method: str, path: str, extra: dict | None = None
) -> None:
    try:
        r = _req(method, path, extra)
        ok = r.status_code == expect
        note = f"got {r.status_code}" + ("" if ok else f" (expected {expect})")
        RESULTS.append((name, ok, note))
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}: {note}")
    except Exception as exc:
        RESULTS.append((name, False, str(exc)))
        print(f"  [FAIL] {name}: {exc}")


def main() -> None:
    print(f"\nPR-CORE-002 production proof — tenant={TENANT}")
    print(f"gateway={GATEWAY_URL}\n")

    req_id = str(uuid.uuid4())

    # G1: valid own-tenant request
    proof_headers = _proof(SECRET, req_id, TENANT, "GET", PROBE_PATH)
    gate("G1 valid-own-tenant", 200, "GET", PROBE_PATH, proof_headers)

    # G2: tenant substitution — proof signed for TENANT, header claims a different tenant
    other = "attacker-tenant"
    subst_headers = {
        **_proof(SECRET, str(uuid.uuid4()), TENANT, "GET", PROBE_PATH),
        "X-Tenant-ID": other,
    }
    gate("G2 tenant-substitution", 403, "GET", PROBE_PATH, subst_headers)

    # G3: method replay — proof signed for GET, request is PUT (both registered on /config)
    # PUT /admin/identity/tenants/{id}/config is a registered route so routing passes;
    # delegation rejects because the canonical method in the proof is GET.
    method_replay = _proof(SECRET, str(uuid.uuid4()), TENANT, "GET", PROBE_PATH)
    gate("G3 method-replay", 403, "PUT", PROBE_PATH, method_replay)

    # G4: path replay — proof signed for /config, request goes to /readiness (registered GET)
    # GET /admin/identity/tenants/{id}/readiness is a registered route so routing passes;
    # delegation rejects because the canonical path in the proof is /config.
    readiness_path = f"/admin/identity/tenants/{TENANT}/readiness"
    path_replay = _proof(SECRET, str(uuid.uuid4()), TENANT, "GET", PROBE_PATH)
    gate("G4 path-replay", 403, "GET", readiness_path, path_replay)

    # G5: missing delegation proof — all delegation headers absent
    gate(
        "G5 missing-delegation-proof",
        403,
        "GET",
        PROBE_PATH,
        {"X-Request-ID": str(uuid.uuid4())},
    )

    # G6: inactive tenant
    if INACTIVE:
        inactive_path = f"/admin/identity/tenants/{INACTIVE}/config"
        inactive_headers = _proof(
            SECRET, str(uuid.uuid4()), INACTIVE, "GET", inactive_path
        )
        inactive_headers["X-Tenant-ID"] = INACTIVE
        base = {**ADMIN_HEADERS, **inactive_headers}
        base["X-Tenant-ID"] = INACTIVE
        gate("G6 inactive-tenant", 403, "GET", inactive_path, inactive_headers)
    else:
        RESULTS.append(
            ("G6 inactive-tenant", False, "SKIPPED — set INACTIVE_TENANT env var")
        )
        print("  [SKIP] G6 inactive-tenant: set INACTIVE_TENANT env var")

    # Summary
    total = len(RESULTS)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n{'=' * 50}")
    print(f"Result: {passed}/{total} PASS")
    if passed < total:
        print("\nFailing gates:")
        for name, ok, note in RESULTS:
            if not ok:
                print(f"  {name}: {note}")
        sys.exit(1)
    else:
        print("PR-CORE-002: PRODUCTION PROVEN")


if __name__ == "__main__":
    main()
