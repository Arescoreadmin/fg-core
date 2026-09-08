from __future__ import annotations

from tests.test_p1139_production_proof import _secret_scan


def test_p1139_evidence_prose_does_not_self_trigger_secret_scan() -> None:
    """Safe evidence prose must not contain credential signatures."""
    evidence = {
        "security_invariants": {
            "no_raw_token_in_response": (
                "PROVEN — invite-initial-admin response contains no token field, "
                "no invitation_url, and no raw workforce invitation credential; "
                "credential delivered via email only"
            )
        }
    }

    assert _secret_scan(evidence) == "CLEAN"


def test_p1139_secret_scan_rejects_actual_workforce_invitation_token_shape() -> None:
    """The scanner must still reject a raw workforce invitation credential."""
    # Build the prefix dynamically so the test source itself does not become
    # evidence containing the sensitive credential signature.
    prefix = "".join(("fg", "wi1", "."))
    evidence = {"leaked_credential": prefix + "synthetic-test-value-not-a-real-secret"}

    result = _secret_scan(evidence)

    assert result != "CLEAN"
    assert "FAIL" in result
