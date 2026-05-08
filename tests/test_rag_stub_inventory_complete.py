from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
REMOVED_MODULE_PATH = REPO / "services" / "ai_plane_extension" / ("rag_" + "stub.py")
REMOVED_SEED_PATH = REPO / "seeds" / ("rag_" + "stub_sources_v1.json")
CI_SCRIPT_PATH = REPO / "tools" / "ci" / ("check_" + "rag_" + "stub_references.py")


def test_legacy_placeholder_retrieval_file_removed() -> None:
    assert not REMOVED_MODULE_PATH.exists()


def test_legacy_placeholder_seed_file_removed() -> None:
    assert not REMOVED_SEED_PATH.exists()


def test_ai_plane_uses_persisted_retrieval_not_placeholder() -> None:
    import services.ai_plane_extension.service as service_mod

    source = Path(service_mod.__file__ or "").read_text(encoding="utf-8")
    assert "retrieve_persisted_rag_context" in source
    assert "retrieve(" not in source
    assert "legacy_placeholder_retrieval" not in source


def test_no_legacy_placeholder_references_remain() -> None:
    pattern = "|".join(["rag_" + "stub", "stub " + "rag", "fake " + "rag"])
    result = subprocess.run(
        ["rg", "-n", pattern, "."],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout


def test_inference_records_do_not_use_legacy_retrieval_id() -> None:
    from services.ai.rag_context import RagContextResult
    from services.ai_plane_extension.service import _rag_retrieval_id

    result = _rag_retrieval_id(
        RagContextResult(
            chunks=(),
            context_text="",
            chunk_count=0,
            source_ids=(),
            retrieval_reason_code="RAG_RETRIEVAL_EMPTY",
            query_phi_sensitivity="none",
            max_sensitivity_level=None,
            contains_phi=False,
            source_chunk_ids=(),
        )
    )
    assert result == "rag:none"


def test_runtime_schema_defaults_to_rag_none() -> None:
    import api.db as db_mod

    source = Path(db_mod.__file__ or "").read_text(encoding="utf-8")
    assert "retrieval_id TEXT NOT NULL DEFAULT 'rag:none'" in source
    assert '"retrieval_id", "TEXT DEFAULT \'rag:none\'"' in source


def test_visibility_script_exits_zero() -> None:
    assert CI_SCRIPT_PATH.exists()
    result = subprocess.run(
        [sys.executable, str(CI_SCRIPT_PATH)],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_removed_placeholder_module_cannot_be_imported() -> None:
    spec = importlib.util.find_spec("services.ai_plane_extension." + "rag_" + "stub")
    assert spec is None
