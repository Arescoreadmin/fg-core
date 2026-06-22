"""SQLAlchemy ORM models for P0-10 Certification Lifecycle Management (CLM) tables.

Mirrors migration 0115.

Classes:
  FaClmCert              — fa_clm_certs (lifecycle_status mutable)
  FaClmLifecycleEvent    — fa_clm_lifecycle_events (append-only)
  FaClmCertReview        — fa_clm_cert_reviews (append-only)
  FaClmCertAttestation   — fa_clm_cert_attestations (append-only)
  FaClmCertRenewal       — fa_clm_cert_renewals (append-only)
  FaClmCertManifest      — fa_clm_cert_manifests (append-only, cert_id UNIQUE)
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaClmCert(Base):
    """Certification Lifecycle Management main cert record.

    Tracks the full lifecycle of a managed certification from draft through
    archival. Only lifecycle_status, status_updated_by, status_updated_at
    mutate after creation.

    cert_type: standard | renewal | exception | interim
    framework: NIST | ISO | SOC | HIPAA | CMMC | internal
    certification_level: bronze | silver | gold | platinum | custom
    lifecycle_status: draft | in_review | pending_evidence | pending_approval |
                      approved | certified | renewal_due | expired | revoked |
                      superseded | archived
    actor_type: human | agent | system | workflow (governance readiness)
    """

    __tablename__ = "fa_clm_certs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    trust_arc_cert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    cert_name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cert_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="standard"
    )
    framework: Mapped[str | None] = mapped_column(String(64), nullable=True)
    certification_level: Mapped[str | None] = mapped_column(String(32), nullable=True)

    lifecycle_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="draft"
    )

    parent_cert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    family_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    valid_from: Mapped[str | None] = mapped_column(String(64), nullable=True)
    valid_until: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_by: Mapped[str] = mapped_column(
        String(255), nullable=False, default="system"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    status_updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status_updated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    cert_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default="human")

    framework_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    certification_profile: Mapped[str | None] = mapped_column(Text, nullable=True)

    generation_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="clm-1.0"
    )
    authority_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="v1"
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaClmLifecycleEvent(Base):
    """Append-only lifecycle event record for a CLM cert.

    Records all status transitions and lifecycle operations:
      status_transition | review_requested | review_completed |
      attestation_added | renewal_initiated | evidence_linked |
      exception_granted | revoked | archived | created
    """

    __tablename__ = "fa_clm_lifecycle_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    actor: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default="human")

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    occurred_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaClmCertReview(Base):
    """Append-only review record for a CLM cert.

    review_outcome: approved | rejected | pending_evidence | exception_requested
    reviewer_type: human | agent | system | workflow
    """

    __tablename__ = "fa_clm_cert_reviews"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    reviewer: Mapped[str] = mapped_column(String(255), nullable=False)
    reviewer_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="human"
    )
    review_outcome: Mapped[str] = mapped_column(String(64), nullable=False)

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    reviewed_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaClmCertAttestation(Base):
    """Append-only attestation record for a CLM cert.

    attestation_type: internal | customer | auditor | executive | agent
    attester_type: human | agent | system | workflow
    attestation_hash: SHA-256(json.dumps(attestation_data, sort_keys=True))
    """

    __tablename__ = "fa_clm_cert_attestations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    attestation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    attester: Mapped[str] = mapped_column(String(255), nullable=False)
    attester_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="human"
    )

    attestation_data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    attestation_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, default=""
    )

    attested_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaClmCertRenewal(Base):
    """Append-only renewal record for a CLM cert.

    renewal_type: routine | emergency | compliance_driven
    renewal_status: initiated | in_progress | completed | abandoned
    renewal_readiness: JSON health snapshot at initiation time
    """

    __tablename__ = "fa_clm_cert_renewals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    renewal_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="routine"
    )
    renewal_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="initiated"
    )

    initiated_by: Mapped[str] = mapped_column(
        String(255), nullable=False, default="system"
    )
    initiated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    new_cert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    renewal_readiness: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaClmCertManifest(Base):
    """Append-only deterministic audit manifest for a CLM cert.

    One manifest per cert (cert_id UNIQUE).
    Contains JSON arrays of every source ID referenced at creation time —
    enabling replay verification and auditor traceability.

    manifest_hash = SHA-256(source ID arrays with sorted keys).
    """

    __tablename__ = "fa_clm_cert_manifests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cert_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    trust_arc_cert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    snapshot_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    bundle_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    timeline_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    decision_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
