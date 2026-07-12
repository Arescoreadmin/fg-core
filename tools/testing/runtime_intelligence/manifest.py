"""Deterministic, cryptographically hashable validation manifests.

A ``ValidationManifest`` captures the exact inputs and outputs of a single
CI validation event (a gate run) in a form that can be:

* canonicalized deterministically (sorted keys, no whitespace, UTF-8),
* hashed independently of volatile fields such as ``created_at``,
* signed with Ed25519, and
* linked into a hash chain via ``previous_manifest_hash``.

The module intentionally has *no* dependency on :mod:`signing` so that the
core hashing/canonicalization primitives can be reused without pulling in the
``cryptography`` library.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime, timezone
from typing import Any

from .models import RuntimeResult
from .serializer import to_json

# ---------------------------------------------------------------------------
# Canonicalization rules
# ---------------------------------------------------------------------------

# Fields excluded from the canonical hash. They are either derived from the
# hash itself (``manifest_id``, ``manifest_hash``), added after signing
# (``signature``, ``signature_algorithm``, ``signing_identity``), added after
# verification (``verification_status``), or intrinsically volatile
# (``created_at``). Excluding the signing fields is essential — the signature
# is computed *over the same pre-image as the hash*, so signing must not
# change the pre-image or verify_hash would break after sign_manifest.
_HASH_EXCLUDED: frozenset[str] = frozenset(
    {
        "manifest_id",
        "manifest_hash",
        "created_at",
        "signature",
        "signature_algorithm",
        "signing_identity",
        "verification_status",
    }
)


@dataclass(frozen=True)
class ValidationManifest:
    """Immutable record describing a signed validation event.

    All fields are ``str`` or ``dict[str, str]`` so serialization stays
    deterministic and no exotic types leak into the hash pre-image.
    """

    schema_version: str
    manifest_version: str
    manifest_id: str
    manifest_hash: str
    previous_manifest_hash: str
    created_at: str
    gate: str
    repository: str
    branch: str
    commit_sha: str
    tree_sha: str
    python_version: str
    runner: str
    platform_info: str
    dependency_fingerprint: str
    environment_fingerprint: str
    selector_fingerprint: str
    manifest_fingerprint: str
    runtime_result_hash: str
    artifact_hashes: dict[str, str] = field(default_factory=dict)
    validation_inputs: dict[str, str] = field(default_factory=dict)
    validation_outputs: dict[str, str] = field(default_factory=dict)
    validation_status: str = "passed"
    signature_algorithm: str = "unsigned"
    signature: str = ""
    signing_identity: str = ""
    verification_status: str = "pending"
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Canonical bytes / hash
# ---------------------------------------------------------------------------


def canonical_bytes(manifest_dict: dict[str, Any]) -> bytes:
    """Return canonical UTF-8 JSON bytes for hashing or signing.

    The output excludes volatile / derived fields, uses sorted keys, no
    whitespace, and ASCII-only escapes. Two manifests whose stable content is
    equal will always produce identical bytes.
    """
    content = {k: v for k, v in manifest_dict.items() if k not in _HASH_EXCLUDED}
    return json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_manifest_hash(manifest_dict: dict[str, Any]) -> str:
    """SHA-256 of the canonical content. Used as both id and hash."""
    return hashlib.sha256(canonical_bytes(manifest_dict)).hexdigest()


# ---------------------------------------------------------------------------
# Dict conversion / serialization
# ---------------------------------------------------------------------------


def manifest_to_dict(m: ValidationManifest) -> dict[str, Any]:
    """Return a plain ``dict`` representation of the manifest.

    ``dataclasses.asdict`` recursively converts nested dicts and preserves
    the original types, so this is safe for the ``dict[str, str]`` fields.
    """
    return asdict(m)


def manifest_from_dict(d: dict[str, Any]) -> ValidationManifest:
    """Deserialize a manifest from a dict.

    Unknown keys are silently ignored so we stay forward-compatible with
    future schema additions. Missing string keys fall back to ``""`` and
    missing dict keys fall back to ``{}``.
    """
    _dict_fields = {
        "artifact_hashes",
        "validation_inputs",
        "validation_outputs",
        "metadata",
    }
    filtered: dict[str, Any] = {}
    for f in fields(ValidationManifest):
        if f.name in d:
            filtered[f.name] = d[f.name]
        elif f.name in _dict_fields:
            filtered[f.name] = {}
        else:
            filtered[f.name] = ""
    return ValidationManifest(**filtered)


def serialize_manifest(m: ValidationManifest) -> str:
    """Deterministic JSON representation of the manifest.

    Unlike :func:`canonical_bytes`, this preserves the *full* manifest —
    including signature and verification status — because it is intended
    for on-disk storage rather than hashing.
    """
    return json.dumps(
        manifest_to_dict(m),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def deserialize_manifest(text: str) -> ValidationManifest:
    """Inverse of :func:`serialize_manifest`."""
    return manifest_from_dict(json.loads(text))


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_manifest(
    result: RuntimeResult,
    gate: str,
    validation_status: str,
    repository: str = "",
    branch: str = "",
    commit_sha: str = "",
    tree_sha: str = "",
    runner: str = "",
    previous_manifest_hash: str = "",
    artifact_hashes: dict[str, str] | None = None,
    validation_inputs: dict[str, str] | None = None,
    validation_outputs: dict[str, str] | None = None,
    metadata: dict[str, str] | None = None,
) -> ValidationManifest:
    """Construct an unsigned :class:`ValidationManifest` from a runtime result.

    The returned manifest is fully populated except for signature material;
    call :func:`signing.sign_manifest` to attach an Ed25519 signature.
    """
    meta = result.meta

    resolved_commit = commit_sha or meta.commit_sha
    resolved_runner = runner or meta.runner_os or platform.system()
    resolved_python = meta.python_version or sys.version.split()[0]
    resolved_platform = f"{platform.system()}/{platform.machine()}"

    runtime_result_hash = hashlib.sha256(to_json(result).encode("utf-8")).hexdigest()

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "manifest_version": "1.0",
        "manifest_id": "",
        "manifest_hash": "",
        "previous_manifest_hash": previous_manifest_hash,
        "created_at": _utc_now_iso(),
        "gate": gate,
        "repository": repository,
        "branch": branch,
        "commit_sha": resolved_commit,
        "tree_sha": tree_sha,
        "python_version": resolved_python,
        "runner": resolved_runner,
        "platform_info": resolved_platform,
        "dependency_fingerprint": meta.dependency_fingerprint,
        "environment_fingerprint": meta.environment_fingerprint,
        "selector_fingerprint": result.selector_fingerprint,
        "manifest_fingerprint": result.manifest_fingerprint,
        "runtime_result_hash": runtime_result_hash,
        "artifact_hashes": dict(artifact_hashes or {}),
        "validation_inputs": dict(validation_inputs or {}),
        "validation_outputs": dict(validation_outputs or {}),
        "validation_status": validation_status,
        "signature_algorithm": "unsigned",
        "signature": "",
        "signing_identity": "",
        "verification_status": "pending",
        "metadata": dict(metadata or {}),
    }

    digest = compute_manifest_hash(payload)
    payload["manifest_id"] = digest
    payload["manifest_hash"] = digest

    return manifest_from_dict(payload)


def with_signature(
    manifest: ValidationManifest,
    signature_hex: str,
    signing_identity: str,
    algorithm: str = "ed25519",
    verification_status: str = "pending",
) -> ValidationManifest:
    """Return a copy of ``manifest`` with signature material attached.

    Kept alongside :class:`ValidationManifest` so callers do not have to know
    that :mod:`dataclasses.replace` works on frozen instances. Note this does
    *not* recompute the hash — signature fields are excluded from the hash
    pre-image by design (see :data:`_HASH_EXCLUDED`).
    """
    return replace(
        manifest,
        signature=signature_hex,
        signing_identity=signing_identity,
        signature_algorithm=algorithm,
        verification_status=verification_status,
    )
