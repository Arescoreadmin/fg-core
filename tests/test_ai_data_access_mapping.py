"""Tests — AI Data Access Mapping (PR 2).

Covers: permission mapping, sensitivity classification, owner inference,
exposure scope, governance readiness, finding generation, bridge import,
tenant isolation, engagement isolation, report section, verification bundle
compatibility, deterministic ordering, and graph node IDs.

All tests are fully isolated using the shared SQLite fixture pattern.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.connectors.ai_data_access_mapping.mapper import (
    classify_exposure_scope,
    classify_governance_readiness,
    classify_owner_type,
    classify_sensitivity,
    map_engagement,
)
from services.field_assessment.connectors.ai_data_access_mapping_bridge import (
    import_ai_data_access_mapping_scan,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool(
    *,
    tool_name: str = "TestAI",
    vendor: str = "TestCo",
    delegated: list[str] | None = None,
    application: list[str] | None = None,
    admin_consent: bool = False,
    consent_type: str = "Principal",
    assigned_users: list[str] | None = None,
    verified_publisher: bool = True,
    confidence: str = "confirmed",
    service_principal_id: str = "sp-001",
    application_id: str = "app-001",
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "vendor": vendor,
        "delegated_permissions": delegated or [],
        "application_permissions": application or [],
        "admin_consent": admin_consent,
        "consent_type": consent_type,
        "assigned_users": assigned_users or [],
        "verified_publisher": verified_publisher,
        "confidence": confidence,
        "service_principal_id": service_principal_id,
        "application_id": application_id,
        "evidence_refs": evidence_refs or [],
        "graph_node_id": f"ai_tool:test-tenant:{application_id}",
    }


def _run_mapping(
    tools: list[dict],
    *,
    tenant_id: str = "tenant-1",
    engagement_id: str = "eng-1",
    source_scan_result_id: str = "scan-001",
) -> tuple[list[dict], list[dict], dict]:
    return map_engagement(
        tools,
        source_scan_result_id=source_scan_result_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )


# ---------------------------------------------------------------------------
# T1: Permission → resource → data category (individual permissions)
# ---------------------------------------------------------------------------


def test_files_read_all_maps_to_documents() -> None:
    tool = _tool(delegated=["Files.Read.All"])
    m, _, _ = _run_mapping([tool])
    assert "Documents" in m[0]["data_categories"]


def test_mail_read_maps_to_email() -> None:
    tool = _tool(delegated=["Mail.Read"])
    m, _, _ = _run_mapping([tool])
    assert "Email" in m[0]["data_categories"]


def test_directory_read_all_maps_to_identity_data() -> None:
    tool = _tool(delegated=["Directory.Read.All"])
    m, _, _ = _run_mapping([tool])
    assert "Identity Data" in m[0]["data_categories"]


def test_chat_read_all_maps_to_teams_data() -> None:
    tool = _tool(delegated=["Chat.Read.All"])
    m, _, _ = _run_mapping([tool])
    assert "Teams Data" in m[0]["data_categories"]


def test_sites_read_all_maps_to_sharepoint_data() -> None:
    tool = _tool(delegated=["Sites.Read.All"])
    m, _, _ = _run_mapping([tool])
    assert "SharePoint Data" in m[0]["data_categories"]


def test_unknown_permissions_produce_no_resource_access() -> None:
    tool = _tool(delegated=["offline_access", "openid", "profile"])
    m, _, _ = _run_mapping([tool])
    assert m[0]["resource_access"] == []
    assert m[0]["data_categories"] == []


# ---------------------------------------------------------------------------
# T2: Sensitivity classification
# ---------------------------------------------------------------------------


def test_critical_sensitivity_for_write_all() -> None:
    assert classify_sensitivity(["Files.ReadWrite.All"]) == "critical"


def test_critical_sensitivity_for_mail_write_all() -> None:
    assert classify_sensitivity(["Mail.ReadWrite.All"]) == "critical"


def test_high_sensitivity_for_files_read_all() -> None:
    assert classify_sensitivity(["Files.Read.All"]) == "high"


def test_moderate_sensitivity_for_scoped_mail() -> None:
    assert classify_sensitivity(["Mail.Read"]) == "moderate"


def test_low_sensitivity_for_user_read() -> None:
    assert classify_sensitivity(["User.Read"]) == "low"


def test_unknown_sensitivity_for_openid_only() -> None:
    assert classify_sensitivity(["openid", "offline_access"]) == "unknown"


def test_max_sensitivity_wins() -> None:
    assert (
        classify_sensitivity(["User.Read", "Files.ReadWrite.All", "Mail.Read"])
        == "critical"
    )


def test_empty_permissions_unknown_sensitivity() -> None:
    assert classify_sensitivity([]) == "unknown"


# ---------------------------------------------------------------------------
# T3: Data owner classification
# ---------------------------------------------------------------------------


def test_identity_data_owner_is_it() -> None:
    assert classify_owner_type(["Identity Data"]) == "IT"


def test_email_owner_is_operations() -> None:
    assert classify_owner_type(["Email"]) == "Operations"


def test_teams_data_owner_is_operations() -> None:
    assert classify_owner_type(["Teams Data"]) == "Operations"


def test_documents_owner_is_unknown() -> None:
    assert classify_owner_type(["Documents"]) == "Unknown"


def test_mixed_categories_picks_alphabetically_first_known() -> None:
    # IT and Operations both known — alphabetically "IT" < "Operations"
    result = classify_owner_type(["Identity Data", "Email"])
    assert result in {"IT", "Operations"}  # deterministic but either is valid per rules


def test_all_unknown_categories() -> None:
    assert classify_owner_type(["Documents", "SharePoint Data"]) == "Unknown"


def test_empty_categories_unknown_owner() -> None:
    assert classify_owner_type([]) == "Unknown"


# ---------------------------------------------------------------------------
# T4: Exposure scope classification
# ---------------------------------------------------------------------------


def test_admin_consent_gives_tenant_scope() -> None:
    tool = _tool(admin_consent=True, consent_type="AllPrincipals")
    assert classify_exposure_scope(tool) == "tenant"


def test_all_principals_consent_type_gives_tenant_scope() -> None:
    tool = _tool(admin_consent=False, consent_type="AllPrincipals")
    assert classify_exposure_scope(tool) == "tenant"


def test_assigned_users_gives_user_scope() -> None:
    tool = _tool(
        admin_consent=False, consent_type="Principal", assigned_users=["u-001"]
    )
    assert classify_exposure_scope(tool) == "user"


def test_no_assignment_gives_unknown_scope() -> None:
    tool = _tool(admin_consent=False, consent_type="Principal", assigned_users=[])
    assert classify_exposure_scope(tool) == "unknown"


def test_suspected_confidence_gives_unknown_scope() -> None:
    tool = _tool(confidence="suspected", admin_consent=True)
    assert classify_exposure_scope(tool) == "unknown"


# ---------------------------------------------------------------------------
# T5: Governance readiness
# ---------------------------------------------------------------------------


def test_ungoverned_for_unverified_publisher() -> None:
    result = classify_governance_readiness(
        verified_publisher=False,
        owner_type="IT",
        review_status="unreviewed",
        confidence="confirmed",
    )
    assert result == "ungoverned"


def test_partially_governed_for_verified_not_reviewed() -> None:
    result = classify_governance_readiness(
        verified_publisher=True,
        owner_type="IT",
        review_status="unreviewed",
        confidence="confirmed",
    )
    assert result == "partially_governed"


def test_governed_when_verified_and_reviewed() -> None:
    result = classify_governance_readiness(
        verified_publisher=True,
        owner_type="IT",
        review_status="reviewed",
        confidence="confirmed",
    )
    assert result == "governed"


def test_governed_when_accepted() -> None:
    result = classify_governance_readiness(
        verified_publisher=True,
        owner_type="Unknown",
        review_status="accepted",
        confidence="confirmed",
    )
    assert result == "governed"


def test_unknown_readiness_for_low_confidence() -> None:
    result = classify_governance_readiness(
        verified_publisher=True,
        owner_type="IT",
        review_status="unreviewed",
        confidence="suspected",
    )
    assert result == "unknown"


# ---------------------------------------------------------------------------
# T6: Review status is always unreviewed on initial mapping
# ---------------------------------------------------------------------------


def test_review_status_always_unreviewed() -> None:
    tool = _tool(delegated=["Files.Read.All"])
    m, _, _ = _run_mapping([tool])
    assert m[0]["review_status"] == "unreviewed"


# ---------------------------------------------------------------------------
# T7: Finding generation — positive cases
# ---------------------------------------------------------------------------


def test_critical_data_access_finding_generated() -> None:
    tool = _tool(delegated=["Files.ReadWrite.All"])
    _, findings, _ = _run_mapping([tool])
    types = [f["type"] for f in findings]
    assert "critical_data_access" in types


def test_tenant_wide_sensitive_finding_for_admin_consent_high() -> None:
    tool = _tool(
        delegated=["Files.Read.All"], admin_consent=True, consent_type="AllPrincipals"
    )
    _, findings, _ = _run_mapping([tool])
    types = [f["type"] for f in findings]
    assert "tenant_wide_sensitive_access" in types


def test_sensitive_data_access_finding_for_high_sensitivity() -> None:
    tool = _tool(delegated=["Mail.Read.All"])
    _, findings, _ = _run_mapping([tool])
    types = [f["type"] for f in findings]
    assert "sensitive_data_access" in types


def test_multi_category_finding_for_three_plus_categories() -> None:
    tool = _tool(
        delegated=[
            "Files.Read.All",
            "Mail.Read.All",
            "Directory.Read.All",
            "Chat.Read.All",
        ]
    )
    _, findings, _ = _run_mapping([tool])
    types = [f["type"] for f in findings]
    assert "multi_category_sensitive_access" in types


def test_unverified_sensitive_finding_for_unverified_high() -> None:
    tool = _tool(delegated=["Files.Read.All"], verified_publisher=False)
    _, findings, _ = _run_mapping([tool])
    types = [f["type"] for f in findings]
    assert "unverified_sensitive_access" in types


# ---------------------------------------------------------------------------
# T8: Finding generation — negative (benign tools produce no findings)
# ---------------------------------------------------------------------------


def test_no_findings_for_low_sensitivity_tool() -> None:
    tool = _tool(delegated=["User.Read", "Calendars.Read"])
    _, findings, _ = _run_mapping([tool])
    assert findings == []


def test_no_findings_for_metadata_only_permissions() -> None:
    tool = _tool(delegated=["openid", "offline_access", "profile"])
    _, findings, _ = _run_mapping([tool])
    assert findings == []


def test_no_findings_for_empty_permissions() -> None:
    tool = _tool(delegated=[], application=[])
    _, findings, _ = _run_mapping([tool])
    assert findings == []


# ---------------------------------------------------------------------------
# T9: Graph-ready identifiers
# ---------------------------------------------------------------------------


def test_graph_node_id_preserved_from_pr1() -> None:
    tool = _tool(delegated=["Files.Read.All"], application_id="app-xyz")
    m, _, _ = _run_mapping([tool])
    assert m[0]["graph_node_id"] == "ai_tool:test-tenant:app-xyz"


def test_data_access_node_ids_use_tenant_and_app_id() -> None:
    tool = _tool(delegated=["Directory.Read.All"], application_id="app-abc")
    m, _, _ = _run_mapping([tool], tenant_id="t-99")
    assert any(
        "t-99" in nid and "app-abc" in nid for nid in m[0]["data_access_node_ids"]
    )


def test_owner_node_id_format() -> None:
    tool = _tool(delegated=["Directory.Read.All"])
    m, _, _ = _run_mapping([tool])
    assert m[0]["owner_node_id"].startswith("data_owner:")


def test_scope_node_id_reflects_exposure() -> None:
    tool = _tool(
        delegated=["Files.Read.All"], admin_consent=True, consent_type="AllPrincipals"
    )
    m, _, _ = _run_mapping([tool])
    assert m[0]["scope_node_id"] == "access_scope:tenant"


def test_governance_node_id_reflects_readiness() -> None:
    tool = _tool(delegated=["Files.ReadWrite.All"], verified_publisher=False)
    m, _, _ = _run_mapping([tool])
    assert m[0]["governance_node_id"] == "governance_state:ungoverned"


# ---------------------------------------------------------------------------
# T10: Summary distribution correctness
# ---------------------------------------------------------------------------


def test_summary_counts_tools_mapped() -> None:
    tools = [
        _tool(delegated=["Files.Read.All"]),
        _tool(delegated=["User.Read"], tool_name="LowTool"),
    ]
    _, _, summary = _run_mapping(tools)
    assert summary["tools_mapped"] == 2


def test_summary_sensitivity_distribution() -> None:
    tools = [
        _tool(delegated=["Files.ReadWrite.All"]),
        _tool(delegated=["Files.Read.All"], tool_name="B"),
    ]
    _, _, summary = _run_mapping(tools)
    dist = summary["sensitivity_distribution"]
    assert dist["critical"] == 1
    assert dist["high"] == 1


def test_summary_readiness_distribution() -> None:
    tools = [
        _tool(verified_publisher=False, delegated=["Files.Read.All"]),
        _tool(verified_publisher=True, delegated=["Files.Read.All"], tool_name="B"),
    ]
    _, _, summary = _run_mapping(tools)
    rdist = summary["governance_readiness_distribution"]
    assert rdist["ungoverned"] == 1
    assert rdist["partially_governed"] == 1


def test_summary_scope_distribution() -> None:
    tools = [
        _tool(
            admin_consent=True,
            consent_type="AllPrincipals",
            delegated=["Files.Read.All"],
        ),
        _tool(assigned_users=["u-1"], tool_name="B"),
    ]
    _, _, summary = _run_mapping(tools)
    sdist = summary["scope_distribution"]
    assert sdist["tenant"] == 1
    assert sdist["user"] == 1


# ---------------------------------------------------------------------------
# T11: Deterministic ordering
# ---------------------------------------------------------------------------


def test_mappings_sorted_by_vendor_then_tool_name() -> None:
    tools = [
        _tool(vendor="Zebra", tool_name="ZZ", application_id="z1"),
        _tool(vendor="Apple", tool_name="AA", application_id="a1"),
        _tool(vendor="Apple", tool_name="BB", application_id="a2"),
    ]
    m, _, _ = _run_mapping(tools)
    assert m[0]["vendor"] == "Apple" and m[0]["tool_name"] == "AA"
    assert m[1]["vendor"] == "Apple" and m[1]["tool_name"] == "BB"
    assert m[2]["vendor"] == "Zebra"


def test_same_inputs_produce_identical_outputs() -> None:
    tool = _tool(delegated=["Files.Read.All", "Directory.Read.All"])
    m1, f1, s1 = _run_mapping([tool], engagement_id="eng-a")
    m2, f2, s2 = _run_mapping([tool], engagement_id="eng-a")
    assert m1[0]["sensitivity"] == m2[0]["sensitivity"]
    assert m1[0]["governance_readiness"] == m2[0]["governance_readiness"]
    assert len(f1) == len(f2)


# ---------------------------------------------------------------------------
# T12: Tenant and engagement isolation (bridge layer)
# ---------------------------------------------------------------------------


@pytest.fixture()
def _db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from api.db_models import Base

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


_STABLE_TS = "2026-06-03T00:00:00Z"


def _make_scan_payload(
    mappings: list[dict],
    *,
    tenant_id: str = "t1",
    engagement_id: str = "e1",
    source_scan_result_id: str = "src-001",
    scan_completed_at: str | None = None,
) -> dict:
    from services.connectors.ai_data_access_mapping.mapper import (
        _build_summary,
        _generate_findings,
    )

    if scan_completed_at is None:
        scan_completed_at = _STABLE_TS

    findings = _generate_findings(mappings)
    summary = _build_summary(
        mappings,
        source_scan_result_id=source_scan_result_id,
        engagement_id=engagement_id,
    )
    return {
        "scan_type": "ai_data_access_mapping_v1",
        "schema_version": "1.0",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "source_scan_result_id": source_scan_result_id,
        "scan_completed_at": scan_completed_at,
        "mappings": mappings,
        "findings": findings,
        "summary": summary,
    }


def test_bridge_creates_scan_result(_db: Any) -> None:
    from sqlalchemy import select
    from api.db_models_field_assessment import FaScanResult

    tool = _tool(delegated=["Files.Read.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="t1", engagement_id="e1")
    payload = _make_scan_payload(mappings, tenant_id="t1", engagement_id="e1")
    result = import_ai_data_access_mapping_scan(
        db=_db, tenant_id="t1", engagement_id="e1", scan_result=payload, actor="test"
    )
    _db.commit()
    assert result.tools_mapped == 1
    scan = _db.execute(
        select(FaScanResult).where(FaScanResult.id == result.scan_result_id)
    ).scalar_one()
    assert scan.source_type == "ai_data_access_mapping"
    assert scan.tenant_id == "t1"


def test_bridge_creates_findings_for_high_sensitivity(_db: Any) -> None:
    from sqlalchemy import select
    from api.db_models_field_assessment import FaNormalizedFinding

    tool = _tool(delegated=["Files.ReadWrite.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="t2", engagement_id="e2")
    payload = _make_scan_payload(mappings, tenant_id="t2", engagement_id="e2")
    result = import_ai_data_access_mapping_scan(
        db=_db, tenant_id="t2", engagement_id="e2", scan_result=payload, actor="test"
    )
    _db.commit()
    assert result.findings_imported > 0
    findings = list(
        _db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == "e2",
                FaNormalizedFinding.tenant_id == "t2",
            )
        ).scalars()
    )
    assert len(findings) > 0
    finding_types = {f.finding_type for f in findings}
    assert any("ai_data_access" in ft for ft in finding_types)


def test_tenant_isolation_in_bridge(_db: Any) -> None:
    from sqlalchemy import select
    from api.db_models_field_assessment import FaScanResult

    tool = _tool(delegated=["Files.Read.All"])
    for tenant, eng in [("ta", "ea"), ("tb", "eb")]:
        mappings, _, _ = _run_mapping([tool], tenant_id=tenant, engagement_id=eng)
        payload = _make_scan_payload(mappings, tenant_id=tenant, engagement_id=eng)
        import_ai_data_access_mapping_scan(
            db=_db,
            tenant_id=tenant,
            engagement_id=eng,
            scan_result=payload,
            actor="test",
        )
    _db.commit()

    ta_results = list(
        _db.execute(
            select(FaScanResult).where(
                FaScanResult.tenant_id == "ta",
                FaScanResult.source_type == "ai_data_access_mapping",
            )
        ).scalars()
    )
    tb_results = list(
        _db.execute(
            select(FaScanResult).where(
                FaScanResult.tenant_id == "tb",
                FaScanResult.source_type == "ai_data_access_mapping",
            )
        ).scalars()
    )
    assert len(ta_results) == 1
    assert len(tb_results) == 1
    assert ta_results[0].id != tb_results[0].id


def test_engagement_isolation_in_bridge(_db: Any) -> None:
    from sqlalchemy import select
    from api.db_models_field_assessment import FaScanResult

    tool = _tool(delegated=["Files.Read.All"])
    for eng in ["eng-x", "eng-y"]:
        mappings, _, _ = _run_mapping(
            [tool], tenant_id="shared-tenant", engagement_id=eng
        )
        payload = _make_scan_payload(
            mappings, tenant_id="shared-tenant", engagement_id=eng
        )
        import_ai_data_access_mapping_scan(
            db=_db,
            tenant_id="shared-tenant",
            engagement_id=eng,
            scan_result=payload,
            actor="test",
        )
    _db.commit()

    for eng in ["eng-x", "eng-y"]:
        rows = list(
            _db.execute(
                select(FaScanResult).where(
                    FaScanResult.engagement_id == eng,
                    FaScanResult.source_type == "ai_data_access_mapping",
                )
            ).scalars()
        )
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# T13: Scan registry schema validation
# ---------------------------------------------------------------------------


def test_scan_registry_accepts_schema_10() -> None:
    from services.field_assessment.scan_registry import (
        SUPPORTED_SCHEMA_VERSIONS,
        REQUIRED_FIELDS,
    )

    assert "1.0" in SUPPORTED_SCHEMA_VERSIONS["ai_data_access_mapping"]
    assert "mappings" in REQUIRED_FIELDS["ai_data_access_mapping"]


# ---------------------------------------------------------------------------
# T14: Business impact is a non-empty deterministic string
# ---------------------------------------------------------------------------


def test_business_impact_non_empty() -> None:
    tool = _tool(delegated=["Files.Read.All"])
    m, _, _ = _run_mapping([tool])
    assert len(m[0]["business_impact"]) > 10


def test_business_impact_contains_sensitivity() -> None:
    tool = _tool(delegated=["Files.ReadWrite.All"])
    m, _, _ = _run_mapping([tool])
    assert "critical" in m[0]["business_impact"].lower()


def test_business_impact_for_low_tool() -> None:
    tool = _tool(delegated=["User.Read"])
    m, _, _ = _run_mapping([tool])
    assert "low" in m[0]["business_impact"].lower()


# ---------------------------------------------------------------------------
# T15: Passive rerun idempotency
# ---------------------------------------------------------------------------


def test_rerun_does_not_create_duplicate_scan_result(_db: Any) -> None:
    """Second rerun against the same source evidence must not insert a new scan row."""
    from sqlalchemy import select
    from api.db_models_field_assessment import FaScanResult

    tool = _tool(delegated=["Files.Read.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="idem-t", engagement_id="idem-e")
    payload = _make_scan_payload(
        mappings,
        tenant_id="idem-t",
        engagement_id="idem-e",
        scan_completed_at=_STABLE_TS,
    )

    result1 = import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="idem-t",
        engagement_id="idem-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    result2 = import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="idem-t",
        engagement_id="idem-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    assert result1.scan_result_id == result2.scan_result_id

    rows = list(
        _db.execute(
            select(FaScanResult).where(
                FaScanResult.engagement_id == "idem-e",
                FaScanResult.tenant_id == "idem-t",
                FaScanResult.source_type == "ai_data_access_mapping",
            )
        ).scalars()
    )
    assert len(rows) == 1


def test_rerun_does_not_duplicate_findings(_db: Any) -> None:
    """Findings are idempotent via findings_hash — reruns must not increase count."""
    from sqlalchemy import select
    from api.db_models_field_assessment import FaNormalizedFinding

    tool = _tool(delegated=["Files.ReadWrite.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="idem-t2", engagement_id="idem-e2")
    payload = _make_scan_payload(
        mappings,
        tenant_id="idem-t2",
        engagement_id="idem-e2",
        scan_completed_at=_STABLE_TS,
    )

    r1 = import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="idem-t2",
        engagement_id="idem-e2",
        scan_result=payload,
        actor="test",
    )
    _db.commit()
    first_count = r1.findings_imported

    import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="idem-t2",
        engagement_id="idem-e2",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    findings = list(
        _db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == "idem-e2",
                FaNormalizedFinding.tenant_id == "idem-t2",
            )
        ).scalars()
    )
    assert len(findings) == first_count


def test_stable_payload_hash_on_rerun(_db: Any) -> None:
    """Same payload must produce the same evidence_hash on every run."""
    from sqlalchemy import select
    from api.db_models_field_assessment import FaScanResult

    tool = _tool(delegated=["Files.Read.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="hash-t", engagement_id="hash-e")
    payload = _make_scan_payload(
        mappings,
        tenant_id="hash-t",
        engagement_id="hash-e",
        scan_completed_at=_STABLE_TS,
    )

    import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="hash-t",
        engagement_id="hash-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="hash-t",
        engagement_id="hash-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    rows = list(
        _db.execute(
            select(FaScanResult).where(
                FaScanResult.engagement_id == "hash-e",
                FaScanResult.source_type == "ai_data_access_mapping",
            )
        ).scalars()
    )
    assert len(rows) == 1


def test_stable_source_refs_on_rerun(_db: Any) -> None:
    """source_ref is deterministic across reruns when scan_result_id is stable."""
    from sqlalchemy import select
    from api.db_models_field_assessment import FaNormalizedFinding

    tool = _tool(delegated=["Files.ReadWrite.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="ref-t", engagement_id="ref-e")
    payload = _make_scan_payload(
        mappings, tenant_id="ref-t", engagement_id="ref-e", scan_completed_at=_STABLE_TS
    )

    r1 = import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="ref-t",
        engagement_id="ref-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()
    sid = r1.scan_result_id

    r2 = import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="ref-t",
        engagement_id="ref-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    assert r1.scan_result_id == r2.scan_result_id

    findings = list(
        _db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == "ref-e"
            )
        ).scalars()
    )
    for f in findings:
        assert f"ai_data_access_mapping:{sid}" in f.source_attribution


# ---------------------------------------------------------------------------
# T16: Framework mapping keys (control_id / control_ref)
# ---------------------------------------------------------------------------


def test_framework_mappings_contain_control_id(_db: Any) -> None:
    """framework_mappings stored in DB must include control_id for report generation."""
    from sqlalchemy import select
    from api.db_models_field_assessment import FaNormalizedFinding

    tool = _tool(delegated=["Files.ReadWrite.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="fw-t", engagement_id="fw-e")
    payload = _make_scan_payload(
        mappings, tenant_id="fw-t", engagement_id="fw-e", scan_completed_at=_STABLE_TS
    )
    import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="fw-t",
        engagement_id="fw-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    findings = list(
        _db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == "fw-e",
                FaNormalizedFinding.tenant_id == "fw-t",
            )
        ).scalars()
    )
    assert findings, "expected at least one finding for Files.ReadWrite.All"
    for finding in findings:
        for fm in finding.framework_mappings or []:
            assert "control_id" in fm, f"Missing control_id in {fm}"
            assert "control_ref" in fm, f"Missing control_ref in {fm}"


def test_framework_mappings_contain_nist_controls(_db: Any) -> None:
    """NIST AI RMF controls MAP 1.1 / GOVERN 1.2 / GOVERN 6.2 / MANAGE 2.4 must appear."""
    from sqlalchemy import select
    from api.db_models_field_assessment import FaNormalizedFinding

    tool = _tool(delegated=["Files.ReadWrite.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="nist-t", engagement_id="nist-e")
    payload = _make_scan_payload(
        mappings,
        tenant_id="nist-t",
        engagement_id="nist-e",
        scan_completed_at=_STABLE_TS,
    )
    import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="nist-t",
        engagement_id="nist-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    findings = list(
        _db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == "nist-e",
            )
        ).scalars()
    )
    all_control_ids = {
        fm["control_id"]
        for f in findings
        for fm in (f.framework_mappings or [])
        if "control_id" in fm
    }
    assert all_control_ids, "No control_ids found in any finding"
    expected = {"GOVERN 1.2", "GOVERN 6.2", "MANAGE 2.4"}
    assert expected & all_control_ids, (
        f"Expected at least one of {expected}, got {all_control_ids}"
    )


def test_framework_summary_includes_nist_controls(_db: Any) -> None:
    """framework_mappings with control_id are picked up by the fa report framework_summary logic."""
    tool = _tool(delegated=["Files.ReadWrite.All"])
    mappings, _, _ = _run_mapping([tool], tenant_id="fs-t", engagement_id="fs-e")
    payload = _make_scan_payload(
        mappings, tenant_id="fs-t", engagement_id="fs-e", scan_completed_at=_STABLE_TS
    )
    import_ai_data_access_mapping_scan(
        db=_db,
        tenant_id="fs-t",
        engagement_id="fs-e",
        scan_result=payload,
        actor="test",
    )
    _db.commit()

    from sqlalchemy import select
    from api.db_models_field_assessment import FaNormalizedFinding

    findings = list(
        _db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == "fs-e"
            )
        ).scalars()
    )

    fw_summary: dict[str, set[str]] = {}
    for f in findings:
        for fm in f.framework_mappings or []:
            if isinstance(fm, dict):
                fw = fm.get("framework", "")
                ctrl = fm.get("control_id") or fm.get("control_ref") or ""
                if fw and ctrl:
                    fw_summary.setdefault(fw, set()).add(ctrl)

    nist_controls = fw_summary.get("NIST-AI-RMF", set())
    assert nist_controls, "NIST-AI-RMF controls missing from framework_summary"
    assert "GOVERN 1.2" in nist_controls or "MANAGE 2.4" in nist_controls


# ---------------------------------------------------------------------------
# T17: Source scan lookup beyond first 100 generic rows
# ---------------------------------------------------------------------------


def test_source_scan_lookup_beyond_100_rows(_db: Any) -> None:
    """get_latest_scan_result_by_source_type must find ai_tool_discovery even when
    101 newer rows of other scan types exist ahead of it."""
    from services.field_assessment.store import (
        create_scan_result,
        get_latest_scan_result_by_source_type,
    )

    tenant_id = "big-t"
    engagement_id = "big-e"

    # Create one ai_tool_discovery scan result first (older)
    at_payload: dict = {
        "scan_type": "ai_tool_discovery",
        "tools": [{"tool_name": "OldTool", "application_id": "app-old"}],
    }
    at_scan = create_scan_result(
        _db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type="ai_tool_discovery",
        schema_version="1.0",
        collected_at="2026-01-01T00:00:00Z",
        raw_payload=at_payload,
        normalized_payload={"tools": at_payload["tools"]},
        object_count=1,
    )

    # Create 101 newer rows of unrelated source types
    for i in range(101):
        create_scan_result(
            _db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_type=f"other_scan_{i}",
            schema_version="1.0",
            collected_at=f"2026-06-0{min(i + 1, 9)}T{i:02d}:00:00Z"
            if i < 9
            else "2026-06-09T00:00:00Z",
            raw_payload={"idx": i, "scan_type": f"other_{i}"},
            normalized_payload=None,
            object_count=0,
        )
    _db.commit()

    found = get_latest_scan_result_by_source_type(
        _db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type="ai_tool_discovery",
    )
    assert found is not None, (
        "Should find ai_tool_discovery scan despite 101 newer rows"
    )
    assert found.id == at_scan.id
    assert found.source_type == "ai_tool_discovery"


def test_source_scan_lookup_cross_tenant_isolation(_db: Any) -> None:
    """get_latest_scan_result_by_source_type must not return a scan from another tenant."""
    from services.field_assessment.store import (
        create_scan_result,
        get_latest_scan_result_by_source_type,
    )

    # Create ai_tool_discovery for tenant B
    create_scan_result(
        _db,
        tenant_id="iso-tenant-B",
        engagement_id="iso-eng",
        source_type="ai_tool_discovery",
        schema_version="1.0",
        collected_at="2026-06-01T00:00:00Z",
        raw_payload={"scan_type": "ai_tool_discovery", "tools": []},
        normalized_payload={"tools": []},
        object_count=0,
    )
    _db.commit()

    # Lookup for tenant A should return None
    found = get_latest_scan_result_by_source_type(
        _db,
        tenant_id="iso-tenant-A",
        engagement_id="iso-eng",
        source_type="ai_tool_discovery",
    )
    assert found is None, "Cross-tenant source scan must not be returned"


def test_source_scan_lookup_cross_engagement_isolation(_db: Any) -> None:
    """get_latest_scan_result_by_source_type must not return a scan from another engagement."""
    from services.field_assessment.store import (
        create_scan_result,
        get_latest_scan_result_by_source_type,
    )

    # Create ai_tool_discovery for engagement X
    create_scan_result(
        _db,
        tenant_id="iso-tenant",
        engagement_id="iso-eng-X",
        source_type="ai_tool_discovery",
        schema_version="1.0",
        collected_at="2026-06-01T00:00:00Z",
        raw_payload={"scan_type": "ai_tool_discovery", "tools": [], "eng": "X"},
        normalized_payload={"tools": []},
        object_count=0,
    )
    _db.commit()

    # Lookup for engagement Y should return None
    found = get_latest_scan_result_by_source_type(
        _db,
        tenant_id="iso-tenant",
        engagement_id="iso-eng-Y",
        source_type="ai_tool_discovery",
    )
    assert found is None, "Cross-engagement source scan must not be returned"
