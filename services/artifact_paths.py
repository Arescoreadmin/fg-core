"""Containment for caller-supplied evidence artifact paths (CODEQL-REMEDIATE-005).

Evidence registration (``/evidence/anchors``, ``/evidence/runs/register``)
hashes a file the caller names. That file must live inside the artifact root
(``FG_ARTIFACTS_DIR``, default ``artifacts``), the same root the evidence
writers use. Anything else — absolute paths, ``..`` traversal, or a symlink
inside the root that points out of it — is refused with one fixed error code,
whether or not the target exists, so the check is not an existence oracle.

Shared by ``services.evidence_anchor_extension`` and ``services.evidence_index``
only; both run inside the core API process.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

ARTIFACT_PATH_INVALID = "EVIDENCE_ARTIFACT_PATH_INVALID"
_HASH_CHUNK_BYTES = 1 << 20


class ArtifactPathError(ValueError):
    """The requested artifact path is not inside the artifact root."""

    def __init__(self) -> None:
        super().__init__(ARTIFACT_PATH_INVALID)


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


def sha256_file(path: Path) -> str:
    """SHA-256 of ``path``, read in fixed-size chunks (bounded memory)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()
