#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path("/home/jcosat/Projects/fg-core")

DB_MODELS = REPO_ROOT / "api/db_models.py"
BILLING = REPO_ROOT / "api/billing.py"
AGENT_PHASE2 = REPO_ROOT / "api/agent_phase2.py"


def ensure_contains(text: str, needle: str, insert_after: str) -> str:
    if needle in text:
        return text
    if insert_after not in text:
        raise RuntimeError(f"anchor not found for insertion: {insert_after!r}")
    return text.replace(insert_after, insert_after + needle, 1)


def patch_db_models(text: str) -> str:
    text = ensure_contains(
        text,
        "from typing import Any\n",
        "from datetime import datetime, timezone\n",
    )

    text = text.replace(
        "from sqlalchemy.orm import DeclarativeBase\n",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n",
    )

    # Convert classic Column declarations to SQLAlchemy 2 typed declarations.
    text = re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Column\(",
        r"\1\2: Mapped[Any] = mapped_column(",
        text,
    )

    return text


def patch_billing(text: str) -> str:
    text = ensure_contains(
        text,
        "from typing import Any, Literal, cast\n",
        "from typing import Any, Literal\n",
    )

    replacements = {
        "payload = {": "payload: dict[str, Any] = {",
        "existing = {": "existing: dict[str, Any] = {",
        "incoming = {": "incoming: dict[str, Any] = {",
        "rates = dict(pricing.rates_json or {})": "rates: dict[str, Any] = dict(pricing.rates_json or {})",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    # Avoid dict.get overload noise on object-typed JSON fields.
    text = text.replace(
        'invoice_total = float((row.invoice_json or {}).get("total", 0.0))',
        'invoice_payload = cast(dict[str, Any], row.invoice_json or {})\n    invoice_total = float(invoice_payload.get("total", 0.0))',
    )

    return text


def patch_agent_phase2(text: str) -> str:
    text = ensure_contains(
        text,
        "from typing import Any, cast\n",
        "from fastapi import APIRouter, Depends, HTTPException, Request\n",
    )

    text = text.replace(
        "_CA_CACHE: tuple[rsa.RSAPrivateKey, x509.Certificate] | None = None",
        "_CA_CACHE: tuple[Any, x509.Certificate] | None = None",
    )
    text = text.replace(
        "def _load_or_create_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:",
        "def _load_or_create_ca() -> tuple[Any, x509.Certificate]:",
    )

    text = text.replace(
        "result: dict = Field(default_factory=dict)",
        "result: dict[str, Any] = Field(default_factory=dict)",
    )
    text = text.replace(
        "payload: dict = Field(default_factory=dict, max_length=128)",
        "payload: dict[str, Any] = Field(default_factory=dict)",
    )
    text = text.replace("policy_json: dict", "policy_json: dict[str, Any]")
    text = text.replace(
        "def _sign_command(payload: dict) -> str:",
        "def _sign_command(payload: dict[str, Any]) -> str:",
    )
    text = text.replace(
        "def _verify_policy_hash(policy: dict, policy_hash: str) -> bool:",
        "def _verify_policy_hash(policy: dict[str, Any], policy_hash: str) -> bool:",
    )
    text = text.replace(
        "def _params_hash(payload: dict | None) -> str:",
        "def _params_hash(payload: dict[str, Any] | None) -> str:",
    )
    text = text.replace(
        "params: dict | None = None,", "params: dict[str, Any] | None = None,"
    )
    text = text.replace(
        "extra: dict | None = None,", "extra: dict[str, Any] | None = None,"
    )
    text = text.replace(
        "def _validate_command_payload(command_type: str, payload: dict) -> None:",
        "def _validate_command_payload(command_type: str, payload: dict[str, Any]) -> None:",
    )

    # Pydantic model class dict typing
    text = text.replace(
        "    validators = {\n",
        "    validators: dict[str, type[BaseModel]] = {\n",
    )

    # Stop the RSA-only cache type from poisoning the CA loader path.
    text = text.replace(
        "        _CA_CACHE = (key, cert)\n        return _CA_CACHE\n",
        "        _CA_CACHE = (cast(Any, key), cert)\n        return _CA_CACHE\n",
    )

    return text


def write_if_changed(path: Path, new_text: str) -> None:
    old_text = path.read_text()
    if old_text != new_text:
        path.write_text(new_text)


def main() -> None:
    db_text = DB_MODELS.read_text()
    billing_text = BILLING.read_text()
    agent_text = AGENT_PHASE2.read_text()

    write_if_changed(DB_MODELS, patch_db_models(db_text))
    write_if_changed(BILLING, patch_billing(billing_text))
    write_if_changed(AGENT_PHASE2, patch_agent_phase2(agent_text))

    print("Patched:")
    print(f" - {DB_MODELS}")
    print(f" - {BILLING}")
    print(f" - {AGENT_PHASE2}")


if __name__ == "__main__":
    main()
