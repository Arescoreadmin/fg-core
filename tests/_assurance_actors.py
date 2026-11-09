"""Test-only named human actors for QA decisions (L14-ASSESSMENT-ASSURANCE-001).

QA approval and rejection now require a named human reviewer who did not
contribute to the assessment.  Production resolves that human from OIDC (or a
verified delegation proof).  Tests simulate the OIDC result with the same
``get_actor_context`` dependency override pattern used elsewhere in the suite:
a request carrying ``X-Test-Human-Actor: <subject>[|<role>]`` resolves to an
``oidc_auth0`` ActorContext for the gateway-bound tenant; every other request
uses the real resolver unchanged.

This never forges production identity: it exists only inside the test app.
"""

from typing import Any

HEADER = "X-Test-Human-Actor"
QA_REVIEWER = "auth0|independent-qa-reviewer"


def install_human_actors(app: Any) -> Any:
    from fastapi import Depends, Request
    from sqlalchemy.orm import Session

    from api.actor_context import ROLE_PERMISSIONS, ActorContext
    from api.auth_dispatch import get_actor_context
    from api.deps import auth_ctx_db_session

    def _override(
        request: Request, conn: Session = Depends(auth_ctx_db_session)
    ) -> ActorContext:
        raw = (request.headers.get(HEADER) or "").strip()
        if not raw:
            return get_actor_context(request, conn)
        subject, _, role = raw.rpartition("|")
        role = role or "qa_reviewer"
        tenant = getattr(request.state, "tenant_id", None) or request.headers.get(
            "X-Tenant-ID"
        )
        return ActorContext(
            subject=subject,
            email=f"{subject.split('|')[-1]}@example.test",
            name="Independent QA Reviewer",
            permissions=ROLE_PERMISSIONS.get(role, frozenset()),
            roles=[role],
            auth_source="oidc_auth0",
            tenant_id=tenant,
            email_verified=True,
        )

    app.dependency_overrides[get_actor_context] = _override
    return app


def reviewer(subject: str = QA_REVIEWER, role: str = "qa_reviewer") -> dict[str, str]:
    """Headers that make a request act as a named human reviewer."""
    return {HEADER: f"{subject}|{role}"}
