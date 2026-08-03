"""
api/notifications/email.py — Portal invitation email delivery via Resend.

Config (env vars):
  FG_RESEND_API_KEY              Resend API key (required for delivery)
  FG_EMAIL_FROM_ADDRESS          Sender address (default: FrostGate <noreply@frostgate.ai>)
  FG_PORTAL_INVITATION_BASE_URL  Portal acceptance URL base
                                 (default: https://app.frostgate.ai/accept-invite)
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger("frostgate.notifications.email")

_RESEND_SEND_URL = "https://api.resend.com/emails"


def _api_key() -> str:
    return (os.getenv("FG_RESEND_API_KEY") or "").strip()


def _from_address() -> str:
    return (
        os.getenv("FG_EMAIL_FROM_ADDRESS") or "FrostGate <noreply@frostgate.ai>"
    ).strip()


def _invitation_base_url() -> str:
    return (
        (
            os.getenv("FG_PORTAL_INVITATION_BASE_URL")
            or "https://app.frostgate.ai/accept-invite"
        )
        .strip()
        .rstrip("/")
    )


@dataclass(frozen=True)
class EmailDeliveryResult:
    state: str  # 'sent' | 'failed' | 'skipped'
    message_id: str | None = None
    error_code: str | None = None
    retryable: bool = False


def build_invitation_url(raw_token: str) -> str:
    """Return the canonical portal acceptance URL for this invitation token."""
    return f"{_invitation_base_url()}?token={raw_token}"


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>FrostGate Portal Invitation</title>
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1a1a1a;max-width:600px;margin:40px auto;padding:0 24px;">
  <h1 style="font-size:22px;font-weight:600;margin-bottom:8px;">You've been invited to FrostGate</h1>
  <p style="color:#555;margin-top:0;">You have been granted <strong>{portal_role}</strong> access.</p>
  <p>To accept, click the button below within <strong>{ttl_friendly}</strong>.
     This link is single-use and expires after one acceptance.</p>
  <p style="margin:32px 0;">
    <a href="{invitation_url}"
       style="background:#0f62fe;color:#fff;text-decoration:none;padding:12px 24px;border-radius:4px;font-size:15px;font-weight:500;">
      Accept Invitation
    </a>
  </p>
  <p style="font-size:13px;color:#888;">
    If you did not expect this invitation, you can safely ignore this email.<br>
    This link expires on {expires_human} UTC.
  </p>
</body>
</html>
"""


def _ttl_friendly(expires_at: str) -> str:
    try:
        exp = datetime.fromisoformat(expires_at)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = exp - datetime.now(tz=timezone.utc)
        days = max(1, delta.days)
        return f"{days} day{'s' if days != 1 else ''}"
    except Exception:
        return "7 days"


def _expires_human(expires_at: str) -> str:
    try:
        exp = datetime.fromisoformat(expires_at)
        return exp.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return expires_at


def send_portal_invitation(
    *,
    to_email: str,
    invitation_url: str,
    portal_role: str,
    expires_at: str,
) -> EmailDeliveryResult:
    """
    Send a portal invitation email via Resend.

    Returns EmailDeliveryResult(state='skipped') if FG_RESEND_API_KEY is absent
    (dev operation without email is allowed; the caller must persist this state).
    Returns state='sent' on success, state='failed' on Resend error.  Never raises.
    """
    api_key = _api_key()
    if not api_key:
        log.warning("portal_invitation_email_skipped: FG_RESEND_API_KEY not configured")
        return EmailDeliveryResult(state="skipped", error_code="RESEND_NOT_CONFIGURED")

    html = _HTML_TEMPLATE.format(
        portal_role=portal_role,
        invitation_url=invitation_url,
        ttl_friendly=_ttl_friendly(expires_at),
        expires_human=_expires_human(expires_at),
    )

    payload = {
        "from": _from_address(),
        "to": [to_email],
        "subject": "You've been invited to FrostGate",
        "html": html,
    }

    req = urllib.request.Request(
        _RESEND_SEND_URL,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
    )
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            message_id = str(body.get("id") or "")
            log.info(
                "portal_invitation_email_sent: to=%s message_id=%s",
                to_email,
                message_id,
            )
            return EmailDeliveryResult(state="sent", message_id=message_id)
    except urllib.error.HTTPError as exc:
        raw = b""
        try:
            raw = exc.read()
        except Exception:
            pass
        log.error(
            "portal_invitation_email_failed: HTTP %s from Resend: %s",
            exc.code,
            raw.decode("utf-8", errors="replace")[:256],
        )
        retryable = exc.code in (429, 500, 502, 503, 504)
        if exc.code == 429:
            error_code = "EMAIL_PROVIDER_RATE_LIMITED"
        elif exc.code >= 500:
            error_code = "EMAIL_PROVIDER_UNAVAILABLE"
        else:
            error_code = "EMAIL_PROVIDER_ERROR"
        return EmailDeliveryResult(
            state="failed", error_code=error_code, retryable=retryable
        )
    except Exception as exc:
        log.error("portal_invitation_email_failed: %s", exc)
        return EmailDeliveryResult(
            state="failed",
            error_code="EMAIL_PROVIDER_UNAVAILABLE",
            retryable=True,
        )
