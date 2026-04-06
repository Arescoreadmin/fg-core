#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

MAKEFILE_PATH = Path("Makefile")


CI_BUDGET_BLOCK = """# =============================================================================
# CI Lane Budgets + Scoped Pytest Filters
# =============================================================================

FG_FAST_MAX_SECONDS ?= 300
FG_FAST_WARN_SECONDS ?= 240

PYTEST_FAST_FILTER ?= -m "smoke or contract or security" -m "not slow and not integration and not postgres and not e2e_http"

.PHONY: fg-fast-pytest fg-fast-budget-check fg-security-pytest fg-full-pytest

fg-fast-pytest: venv _require-pytest-venv
\t@set -euo pipefail; \\
\tstart=$$(date +%s); \\
\tFG_ENV=test $(PYTEST_ENV) $(PYTEST) -q $(PYTEST_FAST_FILTER) --durations=25; \\
\tend=$$(date +%s); \\
\tdur=$$((end - start)); \\
\tmkdir -p artifacts/ci; \\
\tprintf '{"lane":"fg-fast","duration_seconds":%s,"warn_seconds":%s,"max_seconds":%s}\\n' "$$dur" "$(FG_FAST_WARN_SECONDS)" "$(FG_FAST_MAX_SECONDS)" > artifacts/ci/fg_fast_duration.json; \\
\techo "fg-fast pytest duration: $$dur sec"; \\
\tif [ "$$dur" -gt "$(FG_FAST_MAX_SECONDS)" ]; then \\
\t\techo "❌ fg-fast exceeded budget ($(FG_FAST_MAX_SECONDS)s)"; \\
\t\texit 1; \\
\telif [ "$$dur" -gt "$(FG_FAST_WARN_SECONDS)" ]; then \\
\t\techo "⚠️ fg-fast nearing budget ($(FG_FAST_WARN_SECONDS)s)"; \\
\tfi

fg-fast-budget-check: venv
\t@set -euo pipefail; \\
\ttest -f artifacts/ci/fg_fast_duration.json || { echo "❌ missing artifacts/ci/fg_fast_duration.json"; exit 1; }; \\
\tdur="$$(python -c 'import json; print(json.load(open("artifacts/ci/fg_fast_duration.json"))["duration_seconds"])')"; \\
\twarn="$$(python -c 'import json; print(json.load(open("artifacts/ci/fg_fast_duration.json"))["warn_seconds"])')"; \\
\tmax_s="$$(python -c 'import json; print(json.load(open("artifacts/ci/fg_fast_duration.json"))["max_seconds"])')"; \\
\techo "fg-fast budget check: duration=$$dur s warn=$$warn s max=$$max_s s"; \\
\ttest "$$dur" -le "$$max_s"

fg-security-pytest: venv _require-pytest-venv
\t@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/security -m "not slow" --durations=25

fg-full-pytest: venv _require-pytest-venv
\t@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q --durations=50
"""

OLD_FG_SECURITY = """# fg-security is a lane target, not a single check.
# Keep it deterministic and scoped: policy validation + invariant coverage + SOC invariants (if already defined).
fg-security: policy-validate required-tests-gate soc-invariants
\t@set -euo pipefail; \\
\t.venv/bin/python tools/testing/security/check_invariant_coverage.py; \\
\techo "fg-security: PASS"
"""

NEW_FG_SECURITY = """# fg-security is a lane target, not a single check.
# Keep it deterministic and scoped: policy validation + invariant coverage + security pytest lane.
fg-security: policy-validate required-tests-gate soc-invariants fg-security-pytest
\t@set -euo pipefail; \\
\t.venv/bin/python tools/testing/security/check_invariant_coverage.py; \\
\techo "fg-security: PASS"
"""

OLD_FG_FAST = """.PHONY: fg-fast fg-fast-ci fg-fast-full fg-full connectors-gate g-fast

connectors-gate: venv _require-pytest-venv
\t@$(MAKE) -s validate-connector-contracts
\t@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_connector_contract_gate.py tests/security/test_connector_control_plane_security.py
\t@$(MAKE) -s route-inventory-audit
\t@$(PY) tools/ci/check_openapi_security_diff.py
\t@$(MAKE) -s check-connectors-rls

.PHONY: fg-fast g-fast fg-fast-ci fg-fast-full fg-full fg-required-summary

fg-fast: venv fg-audit-make fg-contract fg-compile prod-profile-check \\
\tprod-unsafe-config-check security-regression-gates soc-invariants soc-manifest-verify \\
\troute-inventory-audit check-decision-roe test-quality-gate soc-review-sync pr-base-mainline-check \\
\taudit-chain-verify dos-hardening-check sql-migration-percent-guard gap-audit check-connectors-rls \\
\tbp-s0-001-gate bp-s0-005-gate bp-c-001-gate bp-c-002-gate bp-c-003-gate bp-c-004-gate bp-c-005-gate bp-c-006-gate \\
\tbp-m1-006-gate bp-m2-001-gate bp-m2-002-gate bp-m2-003-gate \\
\tbp-m3-001-gate bp-m3-003-gate bp-m3-004-gate bp-m3-005-gate bp-m3-006-gate bp-m3-007-gate bp-d-000-gate \\
\tverify-spine-modules verify-schemas verify-drift align-score pr-fix-log fg-required-summary
\t@$(MAKE) -s test-unit
\t@$(MAKE) -s fg-lint
\t@$(MAKE) -s test-dashboard-p0
\t@$(MAKE) -s sql-migration-percent-guard

# Compat alias
g-fast: fg-fast

fg-fast-ci: fg-fast billing-ledger-verify billing-invoice-verify opa-check control-plane-check

fg-fast-full: fg-fast-ci compliance-chain-verify canonicalization-guard

fg-full: fg-fast-full \\
\taudit-export-test audit-repro-test compliance-registry-test exam-export-test exam-reproduce-test

fg-required-summary:
\t@mkdir -p artifacts/fg-required
\t@echo '{"status":"ok"}' > artifacts/fg-required/summary.json
\t@echo "FG Required Summary: OK" > artifacts/fg-required/summary.md
"""

NEW_FG_FAST = """.PHONY: fg-fast fg-fast-ci fg-fast-full fg-full connectors-gate g-fast

connectors-gate: venv _require-pytest-venv
\t@$(MAKE) -s validate-connector-contracts
\t@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_connector_contract_gate.py tests/security/test_connector_control_plane_security.py
\t@$(MAKE) -s route-inventory-audit
\t@$(PY) tools/ci/check_openapi_security_diff.py
\t@$(MAKE) -s check-connectors-rls

.PHONY: fg-fast g-fast fg-fast-ci fg-fast-full fg-full fg-required-summary

fg-fast: venv fg-audit-make fg-contract fg-compile prod-profile-check \\
\tprod-unsafe-config-check security-regression-gates soc-invariants soc-manifest-verify \\
\troute-inventory-audit check-decision-roe test-quality-gate soc-review-sync pr-base-mainline-check \\
\taudit-chain-verify dos-hardening-check sql-migration-percent-guard gap-audit check-connectors-rls \\
\tbp-s0-001-gate bp-s0-005-gate bp-c-001-gate bp-c-002-gate bp-c-003-gate bp-c-004-gate bp-c-005-gate bp-c-006-gate \\
\tbp-m1-006-gate bp-m2-001-gate bp-m2-002-gate bp-m2-003-gate \\
\tbp-m3-001-gate bp-m3-003-gate bp-m3-004-gate bp-m3-005-gate bp-m3-006-gate bp-m3-007-gate bp-d-000-gate \\
\tverify-spine-modules verify-schemas verify-drift align-score pr-fix-log fg-required-summary
\t@$(MAKE) -s fg-fast-pytest
\t@$(MAKE) -s fg-lint
\t@$(MAKE) -s test-dashboard-p0
\t@$(MAKE) -s sql-migration-percent-guard
\t@$(MAKE) -s fg-fast-budget-check

# Compat alias
g-fast: fg-fast

fg-fast-ci: fg-fast billing-ledger-verify billing-invoice-verify opa-check control-plane-check

fg-fast-full: fg-fast-ci compliance-chain-verify canonicalization-guard

fg-full: fg-fast-full fg-full-pytest \\
\taudit-export-test audit-repro-test compliance-registry-test exam-export-test exam-reproduce-test

fg-required-summary:
\t@mkdir -p artifacts/fg-required
\t@echo '{"status":"ok"}' > artifacts/fg-required/summary.json
\t@echo "FG Required Summary: OK" > artifacts/fg-required/summary.md
"""


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exact block count 1, got {count}")
    return text.replace(old, new, 1)


def remove_existing_budget_block(text: str) -> str:
    start_marker = "# =============================================================================\n# CI Lane Budgets + Scoped Pytest Filters\n# =============================================================================\n"
    if start_marker not in text:
        return text

    start = text.index(start_marker)

    first_target = "\nfg-fast-pytest: venv _require-pytest-venv\n"
    last_target = "\nfg-full-pytest: venv _require-pytest-venv\n"
    if first_target not in text[start:] or last_target not in text[start:]:
        raise RuntimeError(
            "existing CI budget block is malformed; restore Makefile first"
        )

    last_target_start = text.index(last_target, start)
    after_last = text.find(
        "\n# =============================================================================\n",
        last_target_start + len(last_target),
    )
    if after_last == -1:
        raise RuntimeError("could not find end of existing CI budget block")

    return text[:start] + text[after_last + 1 :]


def main() -> int:
    if not MAKEFILE_PATH.exists():
        print("ERROR: Makefile not found", file=sys.stderr)
        return 1

    text = MAKEFILE_PATH.read_text()

    text = remove_existing_budget_block(text)

    anchor = "# =============================================================================\n# Fast lane + audit/compliance\n# =============================================================================\n"
    if anchor not in text:
        raise RuntimeError("fast lane anchor not found")

    text = text.replace(anchor, anchor + "\n" + CI_BUDGET_BLOCK + "\n", 1)
    text = replace_once(text, OLD_FG_SECURITY, NEW_FG_SECURITY, "fg-security")
    text = replace_once(text, OLD_FG_FAST, NEW_FG_FAST, "fg-fast")

    MAKEFILE_PATH.write_text(text)
    print("Makefile patched successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
