from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models import ConnectorCredential


@dataclass(frozen=True)
class _KEK:
    version: str
    key: bytes


def _load_keks() -> tuple[_KEK, dict[str, bytes]]:
    current = (os.getenv("FG_CONNECTOR_KEK_CURRENT_VERSION") or "").strip().lower()
    prefix = "FG_CONNECTOR_KEK_"
    keys: dict[str, bytes] = {}
    for env_name, value in os.environ.items():
        if (
            not env_name.startswith(prefix)
            or env_name == "FG_CONNECTOR_KEK_CURRENT_VERSION"
        ):
            continue
        ver = env_name[len(prefix) :].strip().lower()
        if not ver:
            continue
        keys[ver] = base64.urlsafe_b64decode(value.encode("utf-8"))
    if not current:
        raise RuntimeError("FG_CONNECTOR_KEK_CURRENT_VERSION missing")
    if current not in keys:
        raise RuntimeError("current connector KEK missing")
    return _KEK(version=current, key=keys[current]), keys


def _aad(
    *,
    tenant_id: str,
    connector_id: str,
    principal_id: str,
    credential_id: str,
    kek_version: str,
) -> bytes:
    """
    AES-GCM AAD binds ciphertext to the full identity boundary:
    tenant + connector + principal + credential + kek_version + env.

    This prevents cross-principal substitution within a tenant/connector namespace.
    """
    env = (os.getenv("FG_ENV") or "dev").strip().lower()
    binding = {
        "tenant_id": tenant_id,
        "connector_id": connector_id,
        "principal_id": principal_id,
        "credential_id": credential_id,
        "kek_version": kek_version,
        "env": env,
    }
    return json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _encrypt_secret(
    payload: dict[str, Any],
    *,
    tenant_id: str,
    connector_id: str,
    principal_id: str,
    credential_id: str,
) -> tuple[str, str]:
    current, _ = _load_keks()
    nonce = os.urandom(12)
    aad = _aad(
        tenant_id=tenant_id,
        connector_id=connector_id,
        principal_id=principal_id,
        credential_id=credential_id,
        kek_version=current.version,
    )
    ciphertext = AESGCM(current.key).encrypt(
        nonce,
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        aad,
    )
    blob = {
        "ver": current.version,
        "nonce": base64.urlsafe_b64encode(nonce).decode("utf-8"),
        "ct": base64.urlsafe_b64encode(ciphertext).decode("utf-8"),
    }
    return json.dumps(blob, sort_keys=True), current.version


def _decrypt_secret(
    blob: str,
    *,
    tenant_id: str,
    connector_id: str,
    principal_id: str,
    credential_id: str,
) -> dict[str, Any]:
    payload = json.loads(blob)
    ver = str(payload["ver"]).strip().lower()
    nonce = base64.urlsafe_b64decode(str(payload["nonce"]).encode("utf-8"))
    ct = base64.urlsafe_b64decode(str(payload["ct"]).encode("utf-8"))
    _, keys = _load_keks()
    key = keys.get(ver)
    if key is None:
        raise RuntimeError("missing KEK version for connector secret")
    aad = _aad(
        tenant_id=tenant_id,
        connector_id=connector_id,
        principal_id=principal_id,
        credential_id=credential_id,
        kek_version=ver,
    )
    decoded = json.loads(AESGCM(key).decrypt(nonce, ct, aad).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RuntimeError("invalid decrypted connector payload")
    return decoded


def upsert_credential(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    principal_id: str,
    auth_mode: str,
    secret_payload: dict[str, Any],
    credential_id: str = "primary",
) -> ConnectorCredential:
    ciphertext, kek_version = _encrypt_secret(
        secret_payload,
        tenant_id=tenant_id,
        connector_id=connector_id,
        principal_id=principal_id,
        credential_id=credential_id,
    )
    row = db.execute(
        select(ConnectorCredential).where(
            ConnectorCredential.tenant_id == tenant_id,
            ConnectorCredential.connector_id == connector_id,
            ConnectorCredential.credential_id == credential_id,
            ConnectorCredential.principal_id == principal_id,
            ConnectorCredential.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if row is None:
        row = ConnectorCredential(
            tenant_id=tenant_id,
            connector_id=connector_id,
            credential_id=credential_id,
            principal_id=principal_id,
            auth_mode=auth_mode,
            ciphertext=ciphertext,
            kek_version=kek_version,
        )
        db.add(row)
    else:
        row.auth_mode = auth_mode
        row.ciphertext = ciphertext
        row.kek_version = kek_version
    db.flush()
    return row


def revoke_connector_credentials(
    db: Session, *, tenant_id: str, connector_id: str
) -> int:
    rows = (
        db.execute(
            select(ConnectorCredential).where(
                ConnectorCredential.tenant_id == tenant_id,
                ConnectorCredential.connector_id == connector_id,
                ConnectorCredential.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    for row in rows:
        row.revoked_at = now
    db.flush()
    return len(rows)


def load_active_secret(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    principal_id: str,
    credential_id: str = "primary",
) -> dict[str, Any]:
    row = db.execute(
        select(ConnectorCredential).where(
            ConnectorCredential.tenant_id == tenant_id,
            ConnectorCredential.connector_id == connector_id,
            ConnectorCredential.credential_id == credential_id,
            ConnectorCredential.principal_id == principal_id,
            ConnectorCredential.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if row is None:
        raise RuntimeError("CONNECTOR_CREDENTIAL_NOT_FOUND")
    return _decrypt_secret(
        row.ciphertext,
        tenant_id=tenant_id,
        connector_id=connector_id,
        principal_id=principal_id,
        credential_id=credential_id,
    )
