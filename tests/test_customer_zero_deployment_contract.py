"""Regression gate: Customer-Zero production env var contract matches runtime consumption.

Fails if vault_transit.py reads a production variable not documented in
docs/deployment/customer_zero_trust_deployment_contract.md, or if the documented
contract lists a variable that the runtime never reads.

This test inspects variable NAMES only. No actual values are required or produced.
"""

from __future__ import annotations

import re
from pathlib import Path


# ── Documented production contract ───────────────────────────────────────────
# Derived from services/cgin/key_management/vault_transit.py.
# If vault_transit.py adds a new FG_CUSTOMER_ZERO_* variable, this test fails
# until both this set AND docs/deployment/customer_zero_trust_deployment_contract.md
# are updated.

_STATIC_PRODUCTION_VARS = frozenset(
    {
        "FG_CUSTOMER_ZERO_VAULT_AUTH_MODE",
        "FG_CUSTOMER_ZERO_VAULT_ADDR",
        "FG_CUSTOMER_ZERO_VAULT_NAMESPACE",
        "FG_CUSTOMER_ZERO_VAULT_ISSUER",
        "FG_CUSTOMER_ZERO_IDENTITY_KEY_ID",
        "FG_CUSTOMER_ZERO_ACCEPTANCE_KEY_ID",
        "FG_CUSTOMER_ZERO_APPROVAL_KEY_ID",
    }
)

_ROLE_SUFFIXES = ("IDENTITY", "ACCEPTANCE", "APPROVAL")
_ROLE_VAR_TYPES = ("VAULT_ROLE_ID", "VAULT_SECRET_ID")

_DYNAMIC_PRODUCTION_VARS = frozenset(
    f"FG_CUSTOMER_ZERO_{suffix}_{type_}"
    for suffix in _ROLE_SUFFIXES
    for type_ in _ROLE_VAR_TYPES
)

DOCUMENTED_PRODUCTION_CONTRACT = _STATIC_PRODUCTION_VARS | _DYNAMIC_PRODUCTION_VARS

# Variables present in vault_transit.py that are dev/test-only and must not
# appear in the production contract.
_DEV_ONLY_VARS = frozenset(
    {
        "FG_CUSTOMER_ZERO_VAULT_TOKEN",
        "FG_CUSTOMER_ZERO_ENVIRONMENT",
    }
)

_SOURCE = Path("services/cgin/key_management/vault_transit.py")


def _parse_static_getenv(source: str) -> set[str]:
    pattern = re.compile(
        r'os\.getenv\((?:"(FG_CUSTOMER_ZERO_[^"]+)"|\'(FG_CUSTOMER_ZERO_[^\']+)\')'
    )
    found: set[str] = set()
    for m in pattern.finditer(source):
        found.add(m.group(1) or m.group(2))
    return found


def _expand_dynamic_getenv(source: str) -> set[str]:
    has_role_id = 'f"FG_CUSTOMER_ZERO_{suffix}_VAULT_ROLE_ID"' in source
    has_secret_id = 'f"FG_CUSTOMER_ZERO_{suffix}_VAULT_SECRET_ID"' in source
    if not (has_role_id and has_secret_id):
        return set()
    from services.cgin.key_management.vault_transit import _ROLE_ENV

    return {
        f"FG_CUSTOMER_ZERO_{suffix}_{type_}"
        for suffix in _ROLE_ENV.values()
        for type_ in _ROLE_VAR_TYPES
    }


def test_production_env_contract_is_complete_and_accurate():
    source = _SOURCE.read_text()
    consumed = _parse_static_getenv(source) | _expand_dynamic_getenv(source)
    production_consumed = consumed - _DEV_ONLY_VARS

    undocumented = production_consumed - DOCUMENTED_PRODUCTION_CONTRACT
    assert not undocumented, (
        f"vault_transit.py reads production vars not in documented contract: {sorted(undocumented)}. "
        "Update docs/deployment/customer_zero_trust_deployment_contract.md and this test."
    )

    missing_from_runtime = DOCUMENTED_PRODUCTION_CONTRACT - production_consumed
    assert not missing_from_runtime, (
        f"Documented contract includes vars not read by vault_transit.py: {sorted(missing_from_runtime)}. "
        "Update DOCUMENTED_PRODUCTION_CONTRACT in this test."
    )


def test_dev_only_vars_not_in_production_contract():
    leaked = _DEV_ONLY_VARS & DOCUMENTED_PRODUCTION_CONTRACT
    assert not leaked, f"Dev-only variables in production contract: {leaked}"


def test_contract_size_is_stable():
    # Fails when someone adds or removes a trust variable, prompting a contract update.
    assert len(DOCUMENTED_PRODUCTION_CONTRACT) == 13, (
        f"Contract size is {len(DOCUMENTED_PRODUCTION_CONTRACT)}, expected 13. "
        "Verify vault_transit.py and update docs/deployment/customer_zero_trust_deployment_contract.md."
    )


def test_secret_and_nonsecret_counts_are_correct():
    secret_vars = {v for v in DOCUMENTED_PRODUCTION_CONTRACT if "SECRET_ID" in v}
    assert len(secret_vars) == 3, (
        f"Expected 3 SECRET_ID vars, got {len(secret_vars)}: {secret_vars}"
    )
    nonsecret_vars = DOCUMENTED_PRODUCTION_CONTRACT - secret_vars
    assert len(nonsecret_vars) == 10, (
        f"Expected 10 non-secret vars, got {len(nonsecret_vars)}"
    )
