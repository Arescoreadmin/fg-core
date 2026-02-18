from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location("gen_ai_ev", str(path))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_degraded_index_unavailable(monkeypatch, tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    mod = _load_module(repo / "scripts" / "generate_ai_plane_evidence.py")

    monkeypatch.chdir(tmp_path)
    (tmp_path / "contracts" / "artifacts").mkdir(parents=True, exist_ok=True)
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    (tmp_path / "contracts" / "artifacts" / "ai_plane_evidence.schema.json").write_text(
        '{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}',
        encoding="utf-8",
    )

    monkeypatch.setattr(mod, "_git_sha", lambda: "abc")

    class _FakeSvc:
        def register_run(self, *args, **kwargs):
            raise RuntimeError("down")

    monkeypatch.setattr(mod, "EvidenceIndexService", _FakeSvc)

    class _FakeDB:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def execute(self, *_args, **_kwargs):
            class _R:
                def scalar_one(self):
                    return 0

            return _R()

    monkeypatch.setattr(mod, "init_db", lambda: None)
    monkeypatch.setattr(mod, "get_sessionmaker", lambda: lambda: _FakeDB())

    assert mod.main() == 0
    assert (tmp_path / "artifacts" / "ai_plane_evidence.json").exists()
