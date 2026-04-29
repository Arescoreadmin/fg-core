"""PHI classification result types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SensitivityLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


@dataclass(frozen=True)
class PhiSpan:
    """Span reference for a redaction candidate. Contains offsets, never raw text."""

    start: int
    end: int
    phi_type: str


@dataclass(frozen=True)
class PhiClassificationResult:
    contains_phi: bool
    phi_types: frozenset[str]
    confidence: float  # 0.0–1.0, deterministic heuristic baseline
    sensitivity_level: SensitivityLevel
    redaction_candidates: tuple[PhiSpan, ...]
    reasoning_code: str  # stable string, no free text
