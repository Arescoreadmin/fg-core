"""
api/embeddings/state.py — Embedding pipeline state machine.

Drives PR 21 (embedding generation pipeline) state tracking.
Contracts only — no implementation.
"""

from __future__ import annotations

from enum import Enum


class EmbeddingState(str, Enum):
    """Lifecycle state for a chunk's embedding.

    Transitions:
        pending → processing → completed
                             → failed
        pending → skipped      (chunk too short / policy filtered)
        failed  → pending      (reset for retry)
    """

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

    # --------------------------------------------------------------------------
    # Transition guards
    # --------------------------------------------------------------------------

    def can_transition_to(self, next_state: "EmbeddingState") -> bool:
        """Return True if this → next_state is a valid transition."""
        return next_state in _VALID_TRANSITIONS.get(self, frozenset())

    @classmethod
    def terminal_states(cls) -> frozenset["EmbeddingState"]:
        return frozenset({cls.COMPLETED, cls.SKIPPED})

    @classmethod
    def retryable_states(cls) -> frozenset["EmbeddingState"]:
        return frozenset({cls.FAILED})


_VALID_TRANSITIONS: dict[EmbeddingState, frozenset[EmbeddingState]] = {
    EmbeddingState.PENDING: frozenset(
        {EmbeddingState.PROCESSING, EmbeddingState.SKIPPED}
    ),
    EmbeddingState.PROCESSING: frozenset(
        {EmbeddingState.COMPLETED, EmbeddingState.FAILED}
    ),
    EmbeddingState.FAILED: frozenset({EmbeddingState.PENDING}),
    EmbeddingState.COMPLETED: frozenset(),
    EmbeddingState.SKIPPED: frozenset(),
}
