# Risk Waivers — FrostGate Production

> Explicit risk acceptance for gaps that ship without full remediation.
> **Production-blocking gaps CANNOT be waived.**

## Waiver Rules

1. Waivers may ONLY apply to:
   - `Launch-risk` gaps
   - `Post-launch` gaps

2. `Production-blocking` gaps **CANNOT** be waived under any circumstances

3. Expired waivers automatically **FAIL** builds

4. Waivers expiring within 14 days trigger **WARNINGS** in CI

5. All waivers require:
   - Documented reason
   - Named approver (accountable individual)
   - Explicit expiration date
   - Scheduled review date

---

## Risk Waivers

| Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
|--------|----------|--------|-------------|------------|-------------|

---

## Governance

- **Approval Authority**: Security lead or designated release manager
- **Review Cadence**: All active waivers reviewed at each release milestone
- **Audit Trail**: This file is version-controlled; all changes require PR review
- **Escalation**: Attempts to waive `Production-blocking` gaps are logged and rejected

## Adding a Waiver

1. Confirm gap is NOT `Production-blocking` in `docs/GAP_MATRIX.md`
2. Document business justification in `Reason` column
3. Get explicit approval from authorized approver
4. Set `Expiration` no more than 90 days out
5. Set `Review Date` at least 14 days before expiration
6. Create PR with waiver entry; reference gap ID in commit message
