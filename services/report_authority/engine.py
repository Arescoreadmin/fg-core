"""services/report_authority/engine.py — Business logic for Report Authority.

This engine is the single write authority for fa_report* tables.
No other service writes to these tables directly.

All mutating operations follow the pattern:
  1. Validate inputs (fail-closed)
  2. Enforce tenant isolation via repository
  3. Execute state transition via the formal state machine
  4. Write the audit event (always, never skipped)
  5. Return schema object (never raw ORM)

The engine never exposes raw ORM rows. Real integration with evidence, control,
verification, and remediation services happens later — placeholder scores of 0.5
are used for now per the integration contract.

No imports from services outside this package — coupling is explicit.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_report_authority import FaReport, FaReportBundle
from services.report_authority.hashing import compute_canonical_hash
from services.report_authority.metadata import (
    EXPORT_VERSION,
    GENERATOR_VERSION,
    PROVIDER_VERSION,
)
from services.report_authority.models import (
    IMMUTABLE_LIFECYCLE_STATES,
    REPORT_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    ActorType,
    ExportBundleState,
    ReportLifecycleState,
    validate_lifecycle_transition,
)
from services.report_authority.repository import ReportRepository
from services.report_authority.schemas import (
    BundleResponse,
    CompareReportsRequest,
    GenerateReportRequest,
    HealthResponse,
    PublishReportRequest,
    ReportImmutableState,
    ReportInvalidTransition,
    ReportListResponse,
    ReportManifestResponse,
    ReportNotFound,
    ReportQualityResponse,
    ReportResponse,
    ReportStatisticsResponse,
    VersionComparisonResponse,
    VerifyReportRequest,
)
from services.report_authority.statistics import compute_quality_score
from services.report_authority.validators import (
    validate_report_request,
    validate_tenant_id,
)
from services.report_authority.versioning import ReportVersion


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _new_id() -> str:
    """Return a new UUID4 as a string."""
    return str(uuid.uuid4())


def _now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _report_ref(tenant_id: str, report_id: str) -> str:
    """Derive a stable, human-readable report reference."""
    return f"RPT-{report_id[:8].upper()}"


def _initial_version() -> str:
    """Return the canonical initial version string for a new report."""
    return str(ReportVersion(major=1, minor=0, patch=0))


# Placeholder coverage values — replaced by real integration in a later PR.
_PLACEHOLDER_COVERAGE: float = 0.5


def _build_report_response(row: FaReport) -> ReportResponse:
    """Map an ORM row to a ReportResponse schema object."""
    return ReportResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        report_ref=row.report_ref,
        assessment_id=row.assessment_id,
        report_type=row.report_type,
        lifecycle_state=row.lifecycle_state,
        title=row.title,
        scope=row.scope,
        objectives=row.objectives,
        assessor_id=row.assessor_id,
        reviewer_id=row.reviewer_id,
        quality_score=row.quality_score,
        quality_grade=row.quality_grade,
        evidence_coverage_score=row.evidence_coverage_score,
        verification_coverage_score=row.verification_coverage_score,
        freshness_score=row.freshness_score,
        confidence_score=row.confidence_score,
        report_hash_sha256=row.report_hash_sha256,
        report_hash_sha512=row.report_hash_sha512,
        manifest_hash=row.manifest_hash,
        transparency_root=row.transparency_root,
        schema_version=row.schema_version,
        manifest_schema_version=row.manifest_schema_version,
        generator_version=row.generator_version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        published_at=row.published_at,
        superseded_at=row.superseded_at,
        archived_at=row.archived_at,
    )


def _build_bundle_response(row: FaReportBundle) -> BundleResponse:
    """Map a bundle ORM row to a BundleResponse schema object."""
    return BundleResponse(
        bundle_id=row.id,
        report_id=row.report_id,
        bundle_state=row.bundle_state,
        bundle_hash_sha256=row.bundle_hash_sha256,
        bundle_hash_sha512=row.bundle_hash_sha512,
        bundle_signature=row.bundle_signature,
        contains_pdf=bool(row.contains_pdf),
        contains_html=bool(row.contains_html),
        contains_json=bool(row.contains_json),
        contains_manifest=bool(row.contains_manifest),
        contains_trust_manifest=bool(row.contains_trust_manifest),
        contains_transparency_proof=bool(row.contains_transparency_proof),
        contains_evidence_index=bool(row.contains_evidence_index),
        contains_verification_instructions=bool(row.contains_verification_instructions),
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ReportAuthorityEngine:
    """Single write authority for report generation, publication, and export."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        validate_tenant_id(tenant_id)
        self._db = db
        self._tenant_id = tenant_id
        self._repo = ReportRepository(db=db, tenant_id=tenant_id)

    # ------------------------------------------------------------------
    # generate_report
    # ------------------------------------------------------------------

    def generate_report(
        self,
        request: GenerateReportRequest,
        actor_id: str,
        actor_type: str,
    ) -> ReportResponse:
        """Create and 'generate' a report from a GenerateReportRequest.

        State progression: DRAFT → GENERATING → GENERATED.
        Quality scores are computed from placeholder data until real
        integration with Evidence/Verification/Control authorities is wired.
        Hashes are computed over the canonical report payload.
        """
        validate_report_request(request)

        report_id = _new_id()
        now = _now()
        version = _initial_version()

        # Compute placeholder quality scores
        evidence_coverage = _PLACEHOLDER_COVERAGE
        verification_coverage = _PLACEHOLDER_COVERAGE
        freshness = _PLACEHOLDER_COVERAGE
        confidence = _PLACEHOLDER_COVERAGE
        completeness = _PLACEHOLDER_COVERAGE

        quality_score, quality_grade = compute_quality_score(
            evidence_coverage=evidence_coverage,
            verification_coverage=verification_coverage,
            freshness_score=freshness,
            confidence_score=confidence,
            completeness_score=completeness,
        )

        # Compute canonical hash over report identity payload
        canonical_payload: dict[str, object] = {
            "report_id": report_id,
            "tenant_id": self._tenant_id,
            "assessment_id": request.assessment_id,
            "report_type": request.report_type.value,
            "title": request.title,
            "scope": request.scope,
            "objectives": request.objectives,
            "assessor_id": request.assessor_id,
            "reviewer_id": request.reviewer_id,
            "schema_version": REPORT_SCHEMA_VERSION,
            "generator_version": GENERATOR_VERSION,
            "created_at": now,
        }
        sha256, sha512 = compute_canonical_hash(canonical_payload)

        # Manifest hash over extended payload (includes quality + hashes)
        manifest_payload: dict[str, object] = {
            **canonical_payload,
            "report_hash_sha256": sha256,
            "report_hash_sha512": sha512,
            "quality_score": quality_score,
            "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        }
        manifest_sha256, _ = compute_canonical_hash(manifest_payload)

        row = FaReport(
            id=report_id,
            tenant_id=self._tenant_id,
            report_ref=_report_ref(self._tenant_id, report_id),
            assessment_id=request.assessment_id,
            report_type=request.report_type.value,
            lifecycle_state=ReportLifecycleState.GENERATED.value,
            title=request.title,
            scope=request.scope,
            objectives=request.objectives,
            assessor_id=request.assessor_id,
            reviewer_id=request.reviewer_id,
            branding_config=None,
            regulatory_profile=request.regulatory_profile,
            report_version=version,
            quality_score=quality_score,
            quality_grade=quality_grade,
            evidence_coverage_score=evidence_coverage,
            verification_coverage_score=verification_coverage,
            freshness_score=freshness,
            confidence_score=confidence,
            completeness_score=completeness,
            report_hash_sha256=sha256,
            report_hash_sha512=sha512,
            manifest_hash=manifest_sha256,
            transparency_root=None,
            schema_version=REPORT_SCHEMA_VERSION,
            manifest_schema_version=MANIFEST_SCHEMA_VERSION,
            generator_version=GENERATOR_VERSION,
            created_at=now,
            updated_at=now,
            published_at=None,
            superseded_at=None,
            archived_at=None,
        )
        self._repo.create_report(row)

        self._repo.create_audit_event(
            report_id=report_id,
            event_type="report_generated",
            actor_id=actor_id,
            actor_type=actor_type,
            from_state=None,
            to_state=ReportLifecycleState.GENERATED.value,
            reason="Report generation completed.",
            event_metadata={
                "report_type": request.report_type.value,
                "assessment_id": request.assessment_id,
                "quality_score": quality_score,
                "quality_grade": quality_grade,
            },
        )

        self._db.commit()
        return _build_report_response(row)

    # ------------------------------------------------------------------
    # get_report
    # ------------------------------------------------------------------

    def get_report(self, report_id: str) -> ReportResponse:
        """Return the report for this tenant. Raises ReportNotFound if absent."""
        row = self._repo.get_report(report_id)
        if row is None:
            raise ReportNotFound(
                f"Report {report_id!r} not found for tenant {self._tenant_id!r}."
            )
        return _build_report_response(row)

    # ------------------------------------------------------------------
    # list_reports
    # ------------------------------------------------------------------

    def list_reports(
        self,
        *,
        report_type: Optional[str] = None,
        lifecycle_state: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> ReportListResponse:
        """Return a paginated, tenant-scoped list of reports."""
        items, total = self._repo.list_reports(
            report_type=report_type,
            lifecycle_state=lifecycle_state,
            offset=offset,
            limit=limit,
        )
        return ReportListResponse(
            items=[_build_report_response(r) for r in items],
            total=total,
            offset=offset,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # get_manifest
    # ------------------------------------------------------------------

    def get_manifest(self, report_id: str) -> ReportManifestResponse:
        """Return the manifest for a report. Raises ReportNotFound if absent."""
        row = self._repo.get_report(report_id)
        if row is None:
            raise ReportNotFound(
                f"Report {report_id!r} not found for tenant {self._tenant_id!r}."
            )
        is_immutable = (
            ReportLifecycleState(row.lifecycle_state) in IMMUTABLE_LIFECYCLE_STATES
        )
        return ReportManifestResponse(
            report_id=row.id,
            report_version=row.report_version or _initial_version(),
            schema_version=row.schema_version,
            manifest_schema_version=row.manifest_schema_version,
            authority_versions={
                "generator": row.generator_version,
                "provider": PROVIDER_VERSION,
                "export": EXPORT_VERSION,
            },
            report_hash_sha256=row.report_hash_sha256,
            report_hash_sha512=row.report_hash_sha512,
            manifest_hash=row.manifest_hash,
            transparency_root=row.transparency_root,
            merkle_root=None,
            generation_timestamp=row.created_at,
            generator_version=row.generator_version,
            provider_version=PROVIDER_VERSION,
            export_version=EXPORT_VERSION,
            is_immutable=is_immutable,
        )

    # ------------------------------------------------------------------
    # publish_report
    # ------------------------------------------------------------------

    def publish_report(
        self,
        report_id: str,
        request: PublishReportRequest,
        actor_id: str,
        actor_type: str,
    ) -> ReportResponse:
        """Transition a report to PUBLISHED. Acquires a row lock for safety."""
        row = self._repo.lock_report_for_update(report_id)
        if row is None:
            raise ReportNotFound(
                f"Report {report_id!r} not found for tenant {self._tenant_id!r}."
            )

        from_state = ReportLifecycleState(row.lifecycle_state)
        to_state = ReportLifecycleState.PUBLISHED

        if from_state in IMMUTABLE_LIFECYCLE_STATES:
            raise ReportImmutableState(
                f"Report {report_id!r} is in immutable state {from_state.value!r}; "
                "cannot publish."
            )
        try:
            validate_lifecycle_transition(from_state, to_state)
        except ValueError as exc:
            raise ReportInvalidTransition(str(exc)) from exc

        now = _now()
        row.lifecycle_state = to_state.value
        row.published_at = now
        row.updated_at = now
        self._repo.save_report(row)

        self._repo.create_audit_event(
            report_id=report_id,
            event_type="report_published",
            actor_id=actor_id,
            actor_type=actor_type,
            from_state=from_state.value,
            to_state=to_state.value,
            reason=request.reason,
            event_metadata={"published_at": now},
        )

        self._db.commit()
        return _build_report_response(row)

    # ------------------------------------------------------------------
    # verify_report
    # ------------------------------------------------------------------

    def verify_report(
        self,
        report_id: str,
        request: VerifyReportRequest,
    ) -> dict[str, object]:
        """Record a verifier's integrity check against the report hash.

        Returns a dict with verification result rather than a schema object
        because the verification payload is simple and schema-free at this stage.
        Audit event is always written.
        """
        row = self._repo.get_report(report_id)
        if row is None:
            raise ReportNotFound(
                f"Report {report_id!r} not found for tenant {self._tenant_id!r}."
            )

        verified_at = _now()
        self._repo.create_audit_event(
            report_id=report_id,
            event_type="report_verified",
            actor_id=request.verifier_id,
            actor_type=ActorType.HUMAN.value,
            from_state=row.lifecycle_state,
            to_state=row.lifecycle_state,
            reason=request.verifier_notes,
            event_metadata={
                "verifier_id": request.verifier_id,
                "verified_at": verified_at,
                "report_hash_sha256": row.report_hash_sha256,
            },
        )

        self._db.commit()
        return {
            "report_id": report_id,
            "verifier_id": request.verifier_id,
            "verified_at": verified_at,
            "report_hash_sha256": row.report_hash_sha256,
            "lifecycle_state": row.lifecycle_state,
            "result": "verified",
        }

    # ------------------------------------------------------------------
    # get_bundle
    # ------------------------------------------------------------------

    def get_bundle(self, report_id: str) -> BundleResponse:
        """Return the most recent export bundle for a report.

        If no bundle exists, creates a placeholder PENDING bundle row.
        Raises ReportNotFound if the report itself does not exist.
        """
        row = self._repo.get_report(report_id)
        if row is None:
            raise ReportNotFound(
                f"Report {report_id!r} not found for tenant {self._tenant_id!r}."
            )

        bundle = self._repo.get_bundle_for_report(report_id)
        if bundle is None:
            now = _now()
            bundle = FaReportBundle(
                id=_new_id(),
                tenant_id=self._tenant_id,
                report_id=report_id,
                bundle_state=ExportBundleState.PENDING.value,
                bundle_hash_sha256=None,
                bundle_hash_sha512=None,
                bundle_signature=None,
                contains_pdf=0,
                contains_html=0,
                contains_json=1,
                contains_manifest=1,
                contains_trust_manifest=0,
                contains_transparency_proof=0,
                contains_evidence_index=0,
                contains_verification_instructions=1,
                created_at=now,
                updated_at=now,
                expires_at=None,
            )
            self._repo.create_bundle(bundle)
            self._repo.create_audit_event(
                report_id=report_id,
                event_type="bundle_initiated",
                actor_id="system",
                actor_type=ActorType.SERVICE.value,
                from_state=None,
                to_state=ExportBundleState.PENDING.value,
                reason="Export bundle initiated on first access.",
                event_metadata={"bundle_id": bundle.id},
            )
            self._db.commit()

        return _build_bundle_response(bundle)

    # ------------------------------------------------------------------
    # compare_versions
    # ------------------------------------------------------------------

    def compare_versions(
        self,
        request: CompareReportsRequest,
    ) -> VersionComparisonResponse:
        """Return a structural diff between two report versions.

        At this stage the diff is computed from top-level metadata only;
        section-level diffing is wired in a later integration PR.
        Raises ReportNotFound if either report is absent.
        """
        baseline = self._repo.get_report(request.baseline_report_id)
        if baseline is None:
            raise ReportNotFound(
                f"Baseline report {request.baseline_report_id!r} not found."
            )
        comparison = self._repo.get_report(request.comparison_report_id)
        if comparison is None:
            raise ReportNotFound(
                f"Comparison report {request.comparison_report_id!r} not found."
            )

        baseline_score = baseline.quality_score or 0.0
        comparison_score = comparison.quality_score or 0.0

        return VersionComparisonResponse(
            baseline_report_id=baseline.id,
            comparison_report_id=comparison.id,
            baseline_version=baseline.report_version or _initial_version(),
            comparison_version=comparison.report_version or _initial_version(),
            added_findings=[],
            removed_findings=[],
            changed_findings=[],
            added_controls=[],
            removed_controls=[],
            quality_delta=round(comparison_score - baseline_score, 6),
            generated_at=_now(),
        )

    # ------------------------------------------------------------------
    # get_quality
    # ------------------------------------------------------------------

    def get_quality(self, report_id: str) -> ReportQualityResponse:
        """Return the quality breakdown for a report."""
        row = self._repo.get_report(report_id)
        if row is None:
            raise ReportNotFound(
                f"Report {report_id!r} not found for tenant {self._tenant_id!r}."
            )
        return ReportQualityResponse(
            report_id=row.id,
            quality_score=row.quality_score,
            quality_grade=row.quality_grade,
            evidence_coverage_score=row.evidence_coverage_score,
            verification_coverage_score=row.verification_coverage_score,
            freshness_score=row.freshness_score,
            confidence_score=row.confidence_score,
            completeness_score=getattr(row, "completeness_score", None),
            computed_at=row.updated_at,
        )

    # ------------------------------------------------------------------
    # get_statistics
    # ------------------------------------------------------------------

    def get_statistics(self) -> ReportStatisticsResponse:
        """Return tenant-level report statistics."""
        raw = self._repo.get_statistics()
        by_state: dict[str, int] = raw["by_lifecycle_state"]
        return ReportStatisticsResponse(
            tenant_id=self._tenant_id,
            total_reports=raw["total"],
            by_type=raw["by_type"],
            by_lifecycle_state=by_state,
            by_quality_grade=raw["by_quality_grade"],
            published_count=by_state.get(ReportLifecycleState.PUBLISHED.value, 0),
            failed_count=by_state.get(ReportLifecycleState.FAILED.value, 0),
            generated_this_month=raw["generated_this_month"],
        )

    # ------------------------------------------------------------------
    # health
    # ------------------------------------------------------------------

    def health(self) -> HealthResponse:
        """Return service health status. Always healthy if the DB is reachable."""
        try:
            self._db.execute(__import__("sqlalchemy").text("SELECT 1"))
            db_status = "ok"
        except Exception:
            db_status = "error"

        overall = "ok" if db_status == "ok" else "degraded"
        return HealthResponse(
            status=overall,
            authority="report_authority",
            version=GENERATOR_VERSION,
            schema_version=REPORT_SCHEMA_VERSION,
            checks={"database": db_status},
        )
