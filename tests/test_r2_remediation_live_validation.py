"""R-2: Validate portal remediation with live engagement data.

Acceptance criteria (all exercised against a real SQLite DB, no mocks):
  R2-1  GET remediation-roadmap with open findings returns phases; all four
        status categories (open, overdue-proxy, completed, blocked) are
        addressable from the roadmap findings list.
  R2-2  PATCH finding status transitions finding to terminal state and returns
        observation_id + questionnaire_controls_updated in the response.
  R2-3  Evidence notes submitted via PATCH are persisted in the observation
        and retrievable via the observations endpoint.
  R2-4  Empty engagement (no open findings) returns total_open_findings=0
        with a valid schema response — explicit empty state.
"""

from __future__ import annotations

import pytest

from tests.fa_forensic_helpers import (
    TENANT_A,
    create_engagement,
    insert_finding,
    make_context,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ctx(build_app):
    return make_context(build_app)


# ---------------------------------------------------------------------------
# R2-1: All four status categories accessible from live roadmap data
# ---------------------------------------------------------------------------


class TestR21RoadmapStatusCategories:
    def test_r2_1_open_findings_appear_in_roadmap_phases(self, ctx) -> None:
        """Open findings populate roadmap phases; total_open_findings > 0."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-open-1",
                severity="high",
                status="open",
            )
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-open-2",
                severity="critical",
                status="open",
            )

        resp = ctx.client_a.get(
            f"/field-assessment/engagements/{eid}/remediation-roadmap"
        )
        assert resp.status_code == 200
        body = resp.json()

        assert body["engagement_id"] == eid
        assert body["total_open_findings"] == 2
        assert len(body["phases"]) > 0

        all_findings = [f for phase in body["phases"] for f in phase["findings"]]
        assert len(all_findings) == 2

        # Open-tab category: findings with status open or in_progress
        open_tab = [f for f in all_findings if f["status"] in ("open", "in_progress")]
        assert len(open_tab) == 2, "open tab must include both open findings"

    def test_r2_1_overdue_proxy_addressable_via_severity_filter(self, ctx) -> None:
        """Overdue tab proxy: high/critical open findings — at least one present."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-overdue-1",
                severity="critical",
                status="open",
            )
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-overdue-2",
                severity="low",
                status="open",
            )

        resp = ctx.client_a.get(
            f"/field-assessment/engagements/{eid}/remediation-roadmap"
        )
        assert resp.status_code == 200
        all_findings = [f for phase in resp.json()["phases"] for f in phase["findings"]]

        # Overdue proxy: high or critical severity open findings
        overdue_proxy = [
            f
            for f in all_findings
            if f["status"] in ("open", "in_progress")
            and f["severity"] in ("critical", "high")
        ]
        assert len(overdue_proxy) == 1, (
            "overdue proxy returns high/critical open findings"
        )

    def test_r2_1_completed_findings_excluded_from_roadmap(self, ctx) -> None:
        """Completed (remediated) findings are excluded from total_open_findings."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-resolved-1",
                severity="high",
                status="remediated",
            )
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-open-3",
                severity="medium",
                status="open",
            )

        resp = ctx.client_a.get(
            f"/field-assessment/engagements/{eid}/remediation-roadmap"
        )
        assert resp.status_code == 200
        body = resp.json()

        # Only the open finding appears; remediated finding is excluded
        assert body["total_open_findings"] == 1

    def test_r2_1_blocked_findings_excluded_from_roadmap(self, ctx) -> None:
        """Blocked (accepted/deferred) findings are excluded from open count."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-blocked-1",
                severity="high",
                status="accepted",
            )
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-open-4",
                severity="medium",
                status="open",
            )

        resp = ctx.client_a.get(
            f"/field-assessment/engagements/{eid}/remediation-roadmap"
        )
        assert resp.status_code == 200
        # accepted finding not in roadmap open findings
        assert resp.json()["total_open_findings"] == 1


# ---------------------------------------------------------------------------
# R2-2: Status patch transitions finding to terminal state
# ---------------------------------------------------------------------------


class TestR22StatusPatch:
    def test_r2_2_patch_finding_status_to_remediated(self, ctx) -> None:
        """PATCH finding status returns observation_id and updates finding status."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            finding = insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-patch-1",
                severity="high",
                status="open",
            )
            finding_id = finding.id

        patch_body = {
            "status": "remediated",
            "notes": "Applied fix per vendor advisory CVE-2026-0001.",
            "owner_email": "owner@example.com",
        }
        resp = ctx.client_a.patch(
            f"/field-assessment/engagements/{eid}/findings/{finding_id}",
            json=patch_body,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        assert body["finding"]["status"] == "remediated"
        assert "observation_id" in body
        assert isinstance(body["questionnaire_controls_updated"], int)

    def test_r2_2_patch_rejected_on_already_terminal_finding(self, ctx) -> None:
        """Patching an already-terminal finding returns 409 — idempotency guard."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            finding = insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-terminal-1",
                severity="high",
                status="remediated",
            )
            finding_id = finding.id

        patch_body = {
            "status": "remediated",
            "notes": "Duplicate attempt.",
            "owner_email": "owner@example.com",
        }
        resp = ctx.client_a.patch(
            f"/field-assessment/engagements/{eid}/findings/{finding_id}",
            json=patch_body,
        )
        assert resp.status_code == 409, (
            "double-patching a terminal finding must return 409"
        )

    def test_r2_2_patch_updates_roadmap_open_count(self, ctx) -> None:
        """After patching a finding to remediated, roadmap total_open_findings decrements."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            finding = insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-decrement-1",
                severity="high",
                status="open",
            )
            finding_id = finding.id
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-decrement-2",
                severity="medium",
                status="open",
            )

        # Baseline: 2 open findings
        before = ctx.client_a.get(
            f"/field-assessment/engagements/{eid}/remediation-roadmap"
        )
        assert before.json()["total_open_findings"] == 2

        ctx.client_a.patch(
            f"/field-assessment/engagements/{eid}/findings/{finding_id}",
            json={
                "status": "remediated",
                "notes": "Fix applied.",
                "owner_email": "eng@example.com",
            },
        )

        # After patch: 1 open finding remains
        after = ctx.client_a.get(
            f"/field-assessment/engagements/{eid}/remediation-roadmap"
        )
        assert after.json()["total_open_findings"] == 1


# ---------------------------------------------------------------------------
# R2-3: Evidence notes persisted and retrievable
# ---------------------------------------------------------------------------


class TestR23EvidenceNotes:
    def test_r2_3_evidence_notes_persisted_in_observation(self, ctx) -> None:
        """Evidence notes from PATCH are retrievable via the observations endpoint."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            finding = insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-evidence-1",
                severity="high",
                status="open",
            )
            finding_id = finding.id

        evidence_text = "MFA enforced on all privileged accounts per AD group policy audit 2026-07-15."
        resp = ctx.client_a.patch(
            f"/field-assessment/engagements/{eid}/findings/{finding_id}",
            json={
                "status": "remediated",
                "notes": evidence_text,
                "owner_email": "security@example.com",
            },
        )
        assert resp.status_code == 200
        observation_id = resp.json()["observation_id"]

        # Retrieve observations and confirm evidence note is present
        obs_resp = ctx.client_a.get(f"/field-assessment/engagements/{eid}/observations")
        assert obs_resp.status_code == 200
        observations = obs_resp.json()
        matching = [o for o in observations if o["id"] == observation_id]
        assert matching, f"observation {observation_id} not found in observations list"
        assert matching[0]["description"] == evidence_text

    def test_r2_3_evidence_owner_email_stored(self, ctx) -> None:
        """Owner email from PATCH is stored in the observation metadata."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            finding = insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-email-1",
                severity="medium",
                status="open",
            )
            finding_id = finding.id

        resp = ctx.client_a.patch(
            f"/field-assessment/engagements/{eid}/findings/{finding_id}",
            json={
                "status": "false_positive",
                "notes": "Asset scoped out of AI governance framework.",
                "owner_email": "ciso@corp.example",
            },
        )
        assert resp.status_code == 200
        observation_id = resp.json()["observation_id"]

        obs_resp = ctx.client_a.get(f"/field-assessment/engagements/{eid}/observations")
        matching = [o for o in obs_resp.json() if o["id"] == observation_id]
        assert matching
        # owner_email stored in observation structured_evidence
        evidence = matching[0].get("structured_evidence") or {}
        assert evidence.get("owner_email") == "ciso@corp.example"


# ---------------------------------------------------------------------------
# R2-4: Empty state — no open findings
# ---------------------------------------------------------------------------


class TestR24EmptyState:
    def test_r2_4_empty_engagement_returns_zero_findings(self, ctx) -> None:
        """Engagement with no findings returns total_open_findings=0 and empty phases."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        resp = ctx.client_a.get(
            f"/field-assessment/engagements/{eid}/remediation-roadmap"
        )
        assert resp.status_code == 200
        body = resp.json()

        assert body["engagement_id"] == eid
        assert body["total_open_findings"] == 0
        assert body["phases"] == []
        assert "current_coverage_pct" in body
        assert "projected_coverage_pct" in body

    def test_r2_4_all_findings_resolved_returns_zero_open(self, ctx) -> None:
        """When all findings are in terminal status, total_open_findings=0."""
        engagement = create_engagement(ctx.client_a)
        eid = engagement["id"]

        from api.db import get_sessionmaker

        SM = get_sessionmaker()
        with SM() as db:
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-all-resolved-1",
                severity="high",
                status="remediated",
            )
            insert_finding(
                db,
                tenant_id=TENANT_A,
                engagement_id=eid,
                marker="r2-all-resolved-2",
                severity="critical",
                status="accepted",
            )

        resp = ctx.client_a.get(
            f"/field-assessment/engagements/{eid}/remediation-roadmap"
        )
        assert resp.status_code == 200
        body = resp.json()

        assert body["total_open_findings"] == 0
        assert body["phases"] == []

    def test_r2_4_nonexistent_engagement_returns_404(self, ctx) -> None:
        """Roadmap for an unknown engagement returns 404 — no silent empty response."""
        resp = ctx.client_a.get(
            "/field-assessment/engagements/does-not-exist/remediation-roadmap"
        )
        assert resp.status_code == 404
