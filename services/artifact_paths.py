"""Authorization for caller-named evidence artifacts.

Evidence registration (``/evidence/anchors``, ``/evidence/runs/register``)
hashes a file the caller names. Two independent checks must pass, in order,
before that file is opened:

1. **Containment** (CODEQL-REMEDIATE-005). The path must resolve, symlinks
   included, strictly inside the artifact root (``FG_ARTIFACTS_DIR``, default
   ``artifacts``). Otherwise: ``EVIDENCE_ARTIFACT_PATH_INVALID``, decided from
   the path string alone, so it is not an existence oracle.
2. **Ownership** (EVIDENCE-ARTIFACT-TENANT-AUTH-001). The artifact root is
   shared by every tenant, so containment is not authorization. A tenant may
   use an artifact only when the producer's canonical owner record binds the
   resolved path to that tenant. Today that is ``decision_evidence_artifacts``
   (``api.evidence_artifacts.emit_decision_evidence``), which also records the
   artifact's SHA-256. Platform artifacts need an explicit, code-defined grant
   (``PLATFORM_ARTIFACT_GRANTS``) that names the owning platform authority, the
   artifact and the permitted operations. Only internal callers can present a
   grant; the HTTP routes never do, so a tenant cannot claim platform evidence.

Foreign, unknown, unowned and owned-but-missing artifacts all raise the same
``ArtifactNotAuthorized`` before any file is read: one response, no oracle.

Shared by ``services.evidence_anchor_extension`` and ``services.evidence_index``
only; both run inside the core API process.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models import DecisionEvidenceArtifact

ARTIFACT_PATH_INVALID = "EVIDENCE_ARTIFACT_PATH_INVALID"
ARTIFACT_NOT_FOUND = "EVIDENCE_ARTIFACT_NOT_FOUND"
ARTIFACT_INTEGRITY_MISMATCH = "EVIDENCE_ARTIFACT_INTEGRITY_MISMATCH"
_HASH_CHUNK_BYTES = 1 << 20


class ArtifactPathError(ValueError):
    """The requested artifact path is not inside the artifact root."""

    def __init__(self) -> None:
        super().__init__(ARTIFACT_PATH_INVALID)


class ArtifactNotAuthorized(LookupError):
    """No owner record (or platform grant) authorizes this caller to use the
    artifact. Deliberately the same for foreign, unknown and missing."""

    def __init__(self) -> None:
        super().__init__(ARTIFACT_NOT_FOUND)


class ArtifactIntegrityError(RuntimeError):
    """The caller's own artifact no longer matches its recorded fingerprint."""

    def __init__(self) -> None:
        super().__init__(ARTIFACT_INTEGRITY_MISMATCH)


@dataclass(frozen=True)
class PlatformArtifactGrant:
    """A platform-owned artifact an internal producer may use.

    Grants live in code, so adding or revoking one is a reviewed change.
    """

    owner: str
    plane_id: str
    artifact_type: str
    operations: frozenset[str]


# Keyed by the artifact's path relative to the artifact root.
PLATFORM_ARTIFACT_GRANTS: dict[str, PlatformArtifactGrant] = {
    "ai_plane_evidence.json": PlatformArtifactGrant(
        owner="services.ai_plane_extension",
        plane_id="ai_plane",
        artifact_type="ai_plane_evidence",
        operations=frozenset({"register_run"}),
    ),
}


@dataclass(frozen=True)
class AuthorizedArtifact:
    path: Path
    ref: str
    recorded_sha256: str | None


def artifact_root() -> str:
    """The real (symlink-resolved) artifact root, read at call time."""
    return os.path.realpath(os.getenv("FG_ARTIFACTS_DIR", "artifacts"))


def resolve_contained_artifact(raw: str) -> Path:
    """Resolve ``raw`` to a real path strictly inside the artifact root.

    Relative paths resolve against the working directory, as before, so
    ``artifacts/<name>`` keeps working with the default root.
    """
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise ArtifactPathError()
    root = artifact_root()
    candidate = os.path.realpath(raw)
    if not candidate.startswith(root + os.sep):
        raise ArtifactPathError()
    return Path(candidate)


def authorize_tenant_artifact(
    db: Session, tenant_id: str, raw: str
) -> AuthorizedArtifact:
    """Return the artifact only if ``tenant_id`` owns it per a canonical record.

    ``tenant_id`` must come from the bound credential, never the request body.
    """
    contained = resolve_contained_artifact(raw)
    if not tenant_id or not tenant_id.strip():
        raise ArtifactNotAuthorized()
    row = db.execute(
        select(DecisionEvidenceArtifact.id, DecisionEvidenceArtifact.evidence_sha256)
        .where(
            DecisionEvidenceArtifact.tenant_id == tenant_id,
            DecisionEvidenceArtifact.storage_path == str(contained),
        )
        .order_by(DecisionEvidenceArtifact.id.desc())
        .limit(1)
    ).first()
    if row is None:
        raise ArtifactNotAuthorized()
    return AuthorizedArtifact(
        path=contained,
        ref=f"decision_evidence:{row.id}",
        recorded_sha256=str(row.evidence_sha256),
    )


def authorize_platform_artifact(
    raw: str, *, authority: str, operation: str, plane_id: str, artifact_type: str
) -> AuthorizedArtifact:
    """Return a platform artifact only for the grant's owner and operation."""
    contained = resolve_contained_artifact(raw)
    grant = PLATFORM_ARTIFACT_GRANTS.get(os.path.relpath(contained, artifact_root()))
    if (
        grant is None
        or grant.owner != authority
        or operation not in grant.operations
        or (grant.plane_id, grant.artifact_type) != (plane_id, artifact_type)
    ):
        raise ArtifactNotAuthorized()
    return AuthorizedArtifact(
        path=contained,
        ref=f"platform:{grant.owner}:{os.path.basename(contained)}",
        recorded_sha256=None,
    )


def hash_authorized_artifact(artifact: AuthorizedArtifact) -> str:
    """Hash an authorized tenant artifact and check it against its record.

    A missing file is reported like an unknown one. A changed file is refused,
    so the anchored fingerprint is always the one the producer recorded, even
    if the file is swapped between authorization and read.
    """
    if not artifact.path.is_file():
        raise ArtifactNotAuthorized()
    digest = sha256_file(artifact.path)
    if artifact.recorded_sha256 is not None and digest != artifact.recorded_sha256:
        raise ArtifactIntegrityError()
    return digest


def sha256_file(path: Path) -> str:
    """SHA-256 of ``path``, read in fixed-size chunks (bounded memory)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()
