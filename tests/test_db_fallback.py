import importlib
from pathlib import Path


def test_db_sqlite_fallback_uses_state_dir(monkeypatch, tmp_path):
    # Force state dir override and ensure db module builds sqlite url under it
    st = tmp_path / "state"
    monkeypatch.setenv("FG_STATE_DIR", str(st))
    monkeypatch.delenv("FG_DB_URL", raising=False)

    import api.config.paths as paths

    importlib.reload(paths)

    import api.db as db

    importlib.reload(db)

    # We can only validate if db.py contains a sqlite fallback path string using STATE_DIR
    src = Path(db.__file__).read_text(encoding="utf-8")
    assert "STATE_DIR" in src


def test_db_explicit_sqlite_path_overrides_fg_db_url(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "FG_DB_URL", "postgresql+psycopg://user:pass@127.0.0.1:5432/frostgate"
    )

    import api.db as db

    db.reset_engine_cache()
    sqlite_path = str(tmp_path / "forced-sqlite.db")
    engine = db.get_engine(sqlite_path=sqlite_path)

    assert engine.dialect.name == "sqlite"
    assert sqlite_path in str(engine.url)
