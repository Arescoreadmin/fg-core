"""Data-driven AI vendor signatures for enterprise discovery.

This module is the authoritative source for AI vendor matching. Connector
code should call the registry instead of scattering vendor-specific logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any


@dataclass(frozen=True)
class AiVendorSignature:
    vendor_name: str
    product_name: str
    known_domains: tuple[str, ...]
    known_publishers: tuple[str, ...]
    known_display_names: tuple[str, ...]
    known_app_ids: tuple[str, ...]
    risk_tags: tuple[str, ...]
    confidence_hints: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor_name": self.vendor_name,
            "product_name": self.product_name,
            "known_domains": list(self.known_domains),
            "known_publishers": list(self.known_publishers),
            "known_display_names": list(self.known_display_names),
            "known_app_ids": list(self.known_app_ids),
            "risk_tags": list(self.risk_tags),
            "confidence_hints": list(self.confidence_hints),
        }


def _norm(value: Any) -> str:
    return " ".join(str(value or "").casefold().replace("_", " ").replace("-", " ").split())


def _norm_domain(value: Any) -> str:
    text = str(value or "").casefold().strip()
    for prefix in ("https://", "http://"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text.split("/", 1)[0].removeprefix("www.")


AI_VENDOR_SIGNATURES: tuple[AiVendorSignature, ...] = (
    AiVendorSignature("Microsoft", "Microsoft Copilot", ("microsoft.com", "copilot.microsoft.com", "graph.microsoft.com"), ("microsoft", "microsoft corporation"), ("microsoft copilot", "copilot for microsoft 365", "m365 copilot"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("OpenAI", "ChatGPT", ("openai.com", "chatgpt.com", "auth.openai.com"), ("openai", "openai opco llc"), ("chatgpt", "openai", "openai chatgpt"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("Anthropic", "Claude", ("anthropic.com", "claude.ai"), ("anthropic", "anthropic pbc"), ("claude", "anthropic claude"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("Google", "Gemini", ("google.com", "gemini.google.com", "ai.google"), ("google", "google llc", "google cloud"), ("gemini", "google gemini", "bard"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("Perplexity", "Perplexity", ("perplexity.ai",), ("perplexity", "perplexity ai"), ("perplexity", "perplexity ai"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("Anysphere", "Cursor", ("cursor.com", "cursor.sh", "anysphere.co"), ("anysphere", "cursor"), ("cursor", "cursor ai", "anysphere"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("GitHub", "GitHub Copilot", ("github.com", "copilot.github.com"), ("github", "github inc", "microsoft"), ("github copilot", "copilot for business"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("Notion", "Notion AI", ("notion.so", "notion.com"), ("notion", "notion labs"), ("notion ai", "notion"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("Grammarly", "Grammarly", ("grammarly.com",), ("grammarly", "grammarly inc"), ("grammarly", "grammarlygo", "grammarly ai"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("Canva", "Canva AI", ("canva.com",), ("canva", "canva pty ltd"), ("canva", "canva ai", "magic studio"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("Salesforce", "Salesforce AI", ("salesforce.com", "force.com"), ("salesforce", "salesforce.com inc"), ("salesforce ai", "einstein", "agentforce"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
    AiVendorSignature("ServiceNow", "ServiceNow AI", ("servicenow.com",), ("servicenow", "service-now.com"), ("servicenow ai", "now assist", "servicenow"), (), ("ai_vendor_detected",), ("publisher", "display_name", "domain")),
)


def match_ai_vendor(
    *,
    display_name: str | None,
    publisher: str | None,
    app_id: str | None,
    domains: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any] | None:
    domains = domains or ()
    norm_name = _norm(display_name)
    norm_publisher = _norm(publisher)
    norm_app_id = str(app_id or "").casefold().strip()
    norm_domains = {_norm_domain(d) for d in domains if d}
    best: tuple[int, list[str], AiVendorSignature] | None = None
    for signature in AI_VENDOR_SIGNATURES:
        reasons: list[str] = []
        score = 0
        if norm_app_id and norm_app_id in {a.casefold() for a in signature.known_app_ids}:
            score += 100
            reasons.append("app_id")
        if norm_publisher and any(p and p in norm_publisher for p in map(_norm, signature.known_publishers)):
            score += 35
            reasons.append("publisher")
        if norm_name:
            names = tuple(map(_norm, signature.known_display_names))
            if any(n and n in norm_name for n in names):
                score += 45
                reasons.append("display_name")
            else:
                fuzzy = max((SequenceMatcher(None, norm_name, n).ratio() for n in names), default=0)
                if fuzzy >= 0.82:
                    score += 25
                    reasons.append("fuzzy_display_name")
        for domain in norm_domains:
            if any(domain == _norm_domain(d) or domain.endswith("." + _norm_domain(d)) for d in signature.known_domains):
                score += 30
                reasons.append("domain")
                break
        if score and (best is None or score > best[0]):
            best = (score, sorted(set(reasons)), signature)
    if best is None:
        return None
    score, reasons, signature = best
    confidence = "confirmed" if score >= 75 else "probable" if score >= 45 else "suspected"
    return {
        "vendor_name": signature.vendor_name,
        "product_name": signature.product_name,
        "confidence": confidence,
        "confidence_score": min(score, 100),
        "match_reasons": reasons,
        "signature": signature.to_dict(),
    }
