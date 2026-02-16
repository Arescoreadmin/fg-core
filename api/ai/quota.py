from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from api.db_models import TenantAIConfig, TenantAIUsage


class QuotaError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        minute_requests: int,
        rpm_limit: int,
        daily_tokens: int,
        daily_budget: int,
    ):
        super().__init__(code)
        self.code = code
        self.minute_requests = minute_requests
        self.rpm_limit = rpm_limit
        self.daily_tokens = daily_tokens
        self.daily_budget = daily_budget


def utc_time_keys(now_utc: datetime) -> tuple[str, str]:
    if now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=timezone.utc)
    now_utc = now_utc.astimezone(timezone.utc)
    return now_utc.strftime("%Y-%m-%d"), now_utc.strftime("%Y-%m-%dT%H:%M")


def _defaults() -> tuple[int, int]:
    rpm = max(1, min(int(os.getenv("FG_AI_RPM", "30")), 600))
    daily = max(
        100, min(int(os.getenv("FG_AI_DAILY_TOKEN_BUDGET", "20000")), 5_000_000)
    )
    return rpm, daily


def enforce_and_consume_quota(
    db: Session,
    *,
    tenant_id: str,
    estimated_tokens: int,
    now_utc: datetime | None = None,
) -> None:
    now = now_utc or datetime.now(timezone.utc)
    day_key, minute_bucket = utc_time_keys(now)

    default_rpm, default_daily = _defaults()
    cfg = db.get(TenantAIConfig, tenant_id)
    rpm_limit = default_rpm
    daily_budget = default_daily
    if cfg and cfg.rpm_limit:
        rpm_limit = min(int(cfg.rpm_limit), default_rpm)
    if cfg and cfg.daily_token_budget:
        daily_budget = min(int(cfg.daily_token_budget), default_daily)

    usage = db.get(TenantAIUsage, (tenant_id, day_key))
    if usage is None:
        usage = TenantAIUsage(tenant_id=tenant_id, usage_day=day_key)
        db.add(usage)
        db.flush()

    if usage.minute_bucket != minute_bucket:
        usage.minute_bucket = minute_bucket
        usage.minute_requests = 0

    if usage.minute_requests >= rpm_limit:
        raise QuotaError(
            "AI_RATE_LIMITED",
            minute_requests=usage.minute_requests,
            rpm_limit=rpm_limit,
            daily_tokens=usage.daily_tokens,
            daily_budget=daily_budget,
        )

    if usage.daily_tokens + estimated_tokens > daily_budget:
        raise QuotaError(
            "AI_BUDGET_EXCEEDED",
            minute_requests=usage.minute_requests,
            rpm_limit=rpm_limit,
            daily_tokens=usage.daily_tokens,
            daily_budget=daily_budget,
        )

    usage.minute_requests += 1
    usage.daily_tokens += estimated_tokens
    db.commit()
