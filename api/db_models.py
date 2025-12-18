from __future__ import annotations

import json
import logging
from datetime import datetime, date
from typing import Any, Iterable, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

log = logging.getLogger("frostgate.db")


class Base(DeclarativeBase):
    pass


def _json_default(o: Any) -> Any:
    """
    Safe JSON serializer for things that show up in FastAPI/Pydantic payloads.
    - datetime/date -> ISO8601
    - bytes -> utf-8 (lossy-safe)
    - fallback -> str(o)
    """
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, bytes):
        try:
            return o.decode("utf-8", errors="replace")
        except Exception:
            return str(o)
    return str(o)


class DecisionRecord(Base):
    __tablename__ = "decisions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_id", name="uq_decisions_tenant_event"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    event_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    threat_level: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    ai_adversarial_score: Mapped[float] = mapped_column(Float, nullable=False)

    pq_fallback: Mapped[bool] = mapped_column(Boolean, nullable=False)

    rules_triggered_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    explain_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    request_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    @staticmethod
    def _dumps(obj: Any) -> str:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,  # ✅ fixes datetime not serializable
        )

    @classmethod
    def from_request_and_response(
        cls,
        *,
        tenant_id: str,
        source: str,
        event_id: str,
        event_type: str,
        threat_level: str,
        anomaly_score: float,
        ai_adversarial_score: float,
        pq_fallback: bool,
        rules_triggered: Iterable[str],
        explain_summary: str,
        latency_ms: int,
        request_obj: Any,
        response_obj: Any,
    ) -> "DecisionRecord":
        return cls(
            tenant_id=tenant_id,
            source=source,
            event_id=event_id,
            event_type=(event_type or "").strip() or "unknown",
            threat_level=threat_level,
            anomaly_score=float(anomaly_score or 0.0),
            ai_adversarial_score=float(ai_adversarial_score or 0.0),
            pq_fallback=bool(pq_fallback),
            rules_triggered_json=cls._dumps(list(rules_triggered)),
            explain_summary=explain_summary,
            latency_ms=int(latency_ms or 0),
            request_json=cls._dumps(request_obj),     # ✅ now safe
            response_json=cls._dumps(response_obj),   # ✅ now safe
        )
