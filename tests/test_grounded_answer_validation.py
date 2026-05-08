"""
PR 18 — Grounded Answer Validation tests.

Proves that:
- AI responses are grounded when tenant corpus context exists.
- Response metadata reflects real persisted chunk IDs.
- No-context path sets safe metadata and does not call provider.
- Audit events include only safe identifiers (no chunk text, no full prompt).
- Wrong-tenant context is not used.
- BAA policy is preserved through the grounded path.
- No live provider calls and no embeddings are invoked.

Selected by: pytest -q tests -k 'grounded'
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest

os.environ.setdefault("FG_ENV", "test")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _configure_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "grounded-validation.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(db_path))


def _seed_corpus_chunks(
    db: Any,
    *,
    tenant_id: str,
    corpus_name: str = "Test Corpus",
    title: str = "Test Document",
    source: str = "https://example.test/doc",
    chunk_texts: list[str],
) -> list[dict[str, Any]]:
    """Seed persisted corpus chunks and return the stored chunk dicts."""
    from api.rag_corpus_store import create_corpus, create_document, store_chunks

    corpus = create_corpus(db, tenant_id=tenant_id, name=corpus_name)
    document = create_document(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title=title,
        source=source,
    )
    return store_chunks(
        db,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[{"text": t, "ordinal": i} for i, t in enumerate(chunk_texts)],
    )


# ---------------------------------------------------------------------------
# 1. Grounded response when corpus context exists
# ---------------------------------------------------------------------------


def test_ai_answer_is_grounded_when_corpus_context_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """used_rag=True and response is returned when relevant corpus chunks exist."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    with get_sessionmaker()() as db:
        stored = _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            chunk_texts=["authentication policy requires mfa for all users"],
        )
        chunk_id = str(stored[0]["chunk_id"])

        def _provider(**kw: Any) -> ProviderResponse:
            return ProviderResponse(
                provider_id="simulated",
                text="authentication policy requires mfa for all users",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )

        result = AIPlaneService().infer(
            db, "tenant-a", AIInferRequest(query="authentication mfa")
        )

    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata["used_rag"] is True
    assert metadata["context_count"] >= 1
    assert chunk_id in metadata["source_chunk_ids"]
    assert result["ok"] is True


def test_grounded_answer_metadata_uses_real_source_chunk_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """source_chunk_ids in metadata must be the real persisted chunk IDs."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    with get_sessionmaker()() as db:
        stored = _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            chunk_texts=["data retention policy controls archive lifecycle"],
        )
        real_chunk_id = str(stored[0]["chunk_id"])
        # Real IDs start with the "ck-" prefix from rag_corpus_store
        assert real_chunk_id.startswith("ck-")

        def _provider(**_kw: Any) -> ProviderResponse:
            return ProviderResponse(
                provider_id="simulated",
                text="data retention policy controls archive lifecycle",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )

        result = AIPlaneService().infer(
            db, "tenant-a", AIInferRequest(query="retention policy controls")
        )

    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata["used_rag"] is True
    assert real_chunk_id in metadata["source_chunk_ids"]
    # No fabricated or placeholder IDs
    for chunk_id in metadata["source_chunk_ids"]:
        assert str(chunk_id).startswith("ck-"), (
            f"source_chunk_ids must be real persisted IDs (prefix ck-), got {chunk_id!r}"
        )


def test_grounded_answer_context_count_matches_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """context_count must equal the number of chunk IDs in source_chunk_ids."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    with get_sessionmaker()() as db:
        _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            chunk_texts=[
                "access control evidence alpha security",
                "access control evidence beta security",
                "access control evidence gamma security",
            ],
        )

        def _provider(**_kw: Any) -> ProviderResponse:
            return ProviderResponse(
                provider_id="simulated",
                text="access control evidence alpha security",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )

        result = AIPlaneService().infer(
            db, "tenant-a", AIInferRequest(query="access control evidence")
        )

    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata["used_rag"] is True
    assert metadata["context_count"] == len(metadata["source_chunk_ids"])
    assert metadata["context_count"] > 0


# ---------------------------------------------------------------------------
# 2. No-context safe fallback
# ---------------------------------------------------------------------------


def test_no_context_sets_no_relevant_context_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When no relevant context exists, metadata must show used_rag=False."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    provider_called = False

    def _provider(**_kw: Any) -> ProviderResponse:
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(provider_id="simulated", text="unused", model="m")

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    result = AIPlaneService().infer(
        get_sessionmaker()(),
        "tenant-a",
        AIInferRequest(query="completely irrelevant query with no matching chunks"),
    )

    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata["used_rag"] is False
    assert metadata["context_count"] == 0
    assert metadata["source_chunk_ids"] == []
    # Provider must not be called when there is no context
    assert provider_called is False


def test_no_context_does_not_fabricate_source_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No-context response must return NO_ANSWER, not fabricated content."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    def _provider(**_kw: Any) -> ProviderResponse:
        # Should never be reached when rag_used=False
        return ProviderResponse(
            provider_id="simulated",
            text="fabricated claim about policy",
            model="m",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    result = AIPlaneService().infer(
        get_sessionmaker()(),
        "tenant-a",
        AIInferRequest(query="xyzzy no matching corpus chunks"),
    )

    # No fabricated source claims
    assert result["response"] == "NO_ANSWER"
    assert result["sources"] == []
    assert result["confidence"] == 0.0
    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata["source_chunk_ids"] == []
    # No fabricated text in response or sources
    assert "fabricated" not in str(result)
    assert "policy" not in str(result.get("response", ""))


# ---------------------------------------------------------------------------
# 3. Audit events / metadata
# ---------------------------------------------------------------------------


def test_retrieval_usage_audit_event_emitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit event must be emitted with rag_used=True when context was retrieved."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    audit_events: list[Any] = []

    with get_sessionmaker()() as db:
        stored = _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            chunk_texts=["audit evidence control policy alpha"],
        )
        chunk_id = str(stored[0]["chunk_id"])

        def _provider(**_kw: Any) -> ProviderResponse:
            return ProviderResponse(
                provider_id="simulated",
                text="audit evidence control policy alpha",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )
        monkeypatch.setattr(
            "api.security_audit.SecurityAuditor.log_event",
            lambda _self, event: audit_events.append(event),
        )

        AIPlaneService().infer(
            db, "tenant-a", AIInferRequest(query="audit evidence control")
        )

    infer_events = [e for e in audit_events if e.reason == "ai_plane_infer"]
    assert infer_events, "Expected at least one ai_plane_infer audit event"
    details = infer_events[-1].details
    assert details["rag_used"] is True
    assert details["rag_chunk_count"] >= 1
    assert chunk_id in details["rag_source_chunk_ids"]


def test_retrieval_audit_does_not_log_chunk_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit metadata must not contain retrieved chunk text."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    audit_events: list[Any] = []
    chunk_text = "secret chunk text that must not appear in audit log"

    with get_sessionmaker()() as db:
        _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            chunk_texts=[chunk_text],
        )

        def _provider(**_kw: Any) -> ProviderResponse:
            return ProviderResponse(
                provider_id="simulated",
                text=chunk_text,
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )
        monkeypatch.setattr(
            "api.security_audit.SecurityAuditor.log_event",
            lambda _self, event: audit_events.append(event),
        )

        AIPlaneService().infer(
            db, "tenant-a", AIInferRequest(query="secret chunk text must not appear")
        )

    infer_details = [e.details for e in audit_events if e.reason == "ai_plane_infer"][
        -1
    ]
    assert chunk_text not in str(infer_details), (
        "Audit metadata must not contain retrieved chunk text"
    )


def test_retrieval_audit_does_not_log_full_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit metadata must not contain the full provider prompt."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    audit_events: list[Any] = []
    captured_prompt: list[str] = []

    with get_sessionmaker()() as db:
        _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            chunk_texts=["prompt isolation evidence control alpha"],
        )

        def _provider(**kw: Any) -> ProviderResponse:
            captured_prompt.append(str(kw["prompt"]))
            return ProviderResponse(
                provider_id="simulated",
                text="prompt isolation evidence control alpha",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )
        monkeypatch.setattr(
            "api.security_audit.SecurityAuditor.log_event",
            lambda _self, event: audit_events.append(event),
        )

        AIPlaneService().infer(
            db, "tenant-a", AIInferRequest(query="prompt isolation evidence")
        )

    assert captured_prompt, "Provider must have been called"
    full_prompt = captured_prompt[0]
    infer_details = [e.details for e in audit_events if e.reason == "ai_plane_infer"][
        -1
    ]
    assert full_prompt not in str(infer_details), (
        "Audit metadata must not contain the full provider prompt"
    )
    # Request/response only appear as hashes
    assert full_prompt not in str(infer_details.get("request_hash", ""))
    assert "Retrieved context:" not in str(infer_details)


# ---------------------------------------------------------------------------
# 4. Tenant isolation
# ---------------------------------------------------------------------------


def test_wrong_tenant_context_not_used_for_grounded_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Context from a different tenant must not appear in the prompt or metadata."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    captured_prompt: list[str] = []

    with get_sessionmaker()() as db:
        _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            corpus_name="Tenant A Corpus",
            chunk_texts=["shared control alpha evidence policy"],
        )
        _seed_corpus_chunks(
            db,
            tenant_id="tenant-b",
            corpus_name="Tenant B Corpus",
            chunk_texts=["shared control beta secret policy"],
        )

        def _provider(**kw: Any) -> ProviderResponse:
            captured_prompt.append(str(kw["prompt"]))
            return ProviderResponse(
                provider_id="simulated",
                text="shared control alpha evidence policy",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )

        result = AIPlaneService().infer(
            db, "tenant-a", AIInferRequest(query="shared control policy")
        )

    assert captured_prompt, "Provider must be called for tenant-a with context"
    prompt_text = captured_prompt[0]
    assert "alpha evidence" in prompt_text
    assert "beta secret" not in prompt_text
    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata["used_rag"] is True
    assert all(cid.startswith("ck-") for cid in metadata["source_chunk_ids"])


# ---------------------------------------------------------------------------
# 5. BAA policy preserved through grounded path
# ---------------------------------------------------------------------------


def test_grounded_answer_path_preserves_baa_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PHI-containing context must trigger BAA gate when provider is not BAA-capable.

    Uses azure_openai (a non-BAA provider in test mode) so the BAA gate fires
    when the retrieved corpus chunk contains PHI terms.
    """
    db_path = tmp_path / "grounded-baa.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "azure_openai")
    monkeypatch.setenv("FG_AZURE_AI_KEY", "test-azure-key")
    monkeypatch.setenv("FG_AZURE_OPENAI_ENDPOINT", "https://azure.example.test")
    monkeypatch.setenv("FG_AZURE_OPENAI_DEPLOYMENT", "fg-test")

    from api.db import get_sessionmaker, init_db, reset_engine_cache
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    provider_called = False

    with get_sessionmaker()() as db:
        _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            chunk_texts=["patient John Smith has diabetes clinical evidence"],
        )

        def _provider(**_kw: Any) -> ProviderResponse:
            nonlocal provider_called
            provider_called = True
            return ProviderResponse(
                provider_id="azure_openai", text="unused", model="m"
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )

        # PHI in retrieved context triggers BAA gate before provider call
        with pytest.raises(ValueError, match="AI_PHI_PROVIDER_NOT_BAA_CAPABLE"):
            AIPlaneService().infer(
                db,
                "tenant-a",
                AIInferRequest(query="clinical evidence"),
            )

    assert provider_called is False


# ---------------------------------------------------------------------------
# 6. No live provider, no embeddings
# ---------------------------------------------------------------------------


def test_grounded_answer_validation_does_not_call_live_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provider dispatch must only be invoked through the monkeypatched mock."""
    _configure_db(tmp_path, monkeypatch)

    from api.db import get_sessionmaker
    from services.ai.providers.base import ProviderResponse
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    live_providers_called: list[str] = []

    def _safe_provider(**kw: Any) -> ProviderResponse:
        provider_id = str(kw.get("provider_id", ""))
        if provider_id not in {"simulated"}:
            live_providers_called.append(provider_id)
        return ProviderResponse(
            provider_id="simulated",
            text="grounded text for provider call",
            model="SIMULATED_V1",
        )

    with get_sessionmaker()() as db:
        _seed_corpus_chunks(
            db,
            tenant_id="tenant-a",
            chunk_texts=["grounded text for provider call"],
        )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _safe_provider
        )

        AIPlaneService().infer(
            db, "tenant-a", AIInferRequest(query="grounded text provider call")
        )

    assert live_providers_called == [], (
        f"Live non-simulated provider was called: {live_providers_called}"
    )


def test_grounded_answer_validation_does_not_call_embeddings() -> None:
    """The grounded-answer validation path must not call any embedding API.

    Checks executable lines only (imports + function calls) — comments are
    excluded so that documentation text like 'no embeddings' does not fail.
    """
    import importlib.util
    import re

    # Lines that could actually execute an embedding/vector API call.
    _EXEC_RE = re.compile(r"^\s*(import |from |[a-zA-Z_].*\()", re.MULTILINE)

    def _executable_lines(text: str) -> str:
        return "\n".join(
            line
            for line in text.splitlines()
            if _EXEC_RE.match(line) and not line.strip().startswith("#")
        ).lower()

    forbidden_calls = ("pgvector", "vector_search", "embed(", "embeddings(")

    spec = importlib.util.find_spec("api.rag_retrieval")
    assert spec is not None and spec.origin is not None
    exec_source = _executable_lines(Path(spec.origin).read_text(encoding="utf-8"))
    for token in forbidden_calls:
        assert token not in exec_source, (
            f"api/rag_retrieval.py must not call {token!r} "
            "(no embeddings in lexical retrieval path)"
        )
    # Import-level check: no embedding library imports
    for token in ("pgvector", "openai", "anthropic"):
        assert token not in exec_source, (
            f"api/rag_retrieval.py must not import {token!r}"
        )

    spec2 = importlib.util.find_spec("services.ai.rag_context")
    assert spec2 is not None and spec2.origin is not None
    exec_source2 = _executable_lines(Path(spec2.origin).read_text(encoding="utf-8"))
    for token in forbidden_calls:
        assert token not in exec_source2, (
            f"services/ai/rag_context.py must not call {token!r}"
        )
