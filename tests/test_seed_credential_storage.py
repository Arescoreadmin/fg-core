"""CODEQL-REMEDIATE-004 — seed credential persistence (CodeQL #8, #9).

``tools/seed/run_seed.py`` persists non-expiring local seed API keys in its
owner-only state file (``state/seed/bootstrap_state.json``). That is the
designed tester hand-off. These tests pin the properties that make it safe:

- the keys in the file are minted against the database the file records,
  never against an inherited ``FG_DB_URL`` (another environment);
- an unsafe state file is refused before any key is minted or rotated;
- rewriting the file is atomic: a failed write keeps the previous complete
  file, and an existing hardlink is never written through;
- the file stays owner-only, and nothing under ``state/`` is tracked by git.

All credential values are synthetic.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from tools.seed import credential_output, run_seed

_OLD_KEYS = {
    "admin_api_key": "fgk.synthetic-old-admin-" + "G" * 20,
    "agent_api_key": "fgk.synthetic-old-agent-" + "H" * 20,
    "audit_api_key": "fgk.synthetic-old-audit-" + "J" * 20,
}
_NEW_KEYS = {
    "admin_api_key": "fgk.synthetic-new-admin-" + "K" * 20,
    "agent_api_key": "fgk.synthetic-new-agent-" + "L" * 20,
    "audit_api_key": "fgk.synthetic-new-audit-" + "M" * 20,
}
_REPO = Path(__file__).resolve().parents[1]


def _config(tmp_path: Path) -> run_seed.SeedConfig:
    return run_seed.SeedConfig(
        sqlite_path=str(tmp_path / "local-seed.db"),
        registry_path=str(tmp_path / "tenants.json"),
        state_path=str(tmp_path / "seed" / "bootstrap_state.json"),
        tenant_id="tenant-seed-primary",
    )


def _write_state(config: run_seed.SeedConfig, keys: dict[str, str]) -> Path:
    state = Path(config.state_path)
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        json.dumps(
            {
                "sqlite_path": config.sqlite_path,
                "tenant_id": config.tenant_id,
                "seed_credentials": dict(keys),
            }
        ),
        encoding="utf-8",
    )
    state.chmod(0o600)
    return state


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def clean_engine():
    from api.db import reset_engine_cache

    reset_engine_cache()
    yield
    reset_engine_cache()


@pytest.fixture
def mint_spy(monkeypatch):
    """Replace minting with a recorder that returns synthetic new keys."""
    calls: list[str] = []

    def _mint(cfg, payload):
        from api.db import get_engine

        calls.append(str(get_engine().url))
        return {**payload, "seed_credentials": dict(_NEW_KEYS)}

    monkeypatch.setattr(run_seed, "_ensure_seed_credentials", _mint)
    return calls


# --- Environment binding (#8 rerun write site) -----------------------------


def test_rerun_mints_against_recorded_database_not_fg_db_url(
    monkeypatch, tmp_path, clean_engine, mint_spy
):
    """An operator shell may still export another environment's FG_DB_URL
    (the demo-tenant flow uses one). The first run pins the recorded SQLite
    database; a rerun must too, or it mints live, non-expiring keys in that
    other environment and stores them under the local database's name."""
    config = _config(tmp_path)
    _write_state(config, _OLD_KEYS)
    other = tmp_path / "other-environment.db"
    monkeypatch.setenv("FG_DB_URL", f"sqlite:///{other}")
    validated: list[str] = []

    def _validate(cfg):
        from api.db import get_engine

        validated.append(str(get_engine().url))

    monkeypatch.setattr(run_seed, "_validate_existing_seed", _validate)

    run_seed._seed_once(config)

    assert mint_spy, "rerun did not reach credential minting"
    for url in validated + mint_spy:
        assert config.sqlite_path in url
        assert str(other) not in url


# --- Refuse before minting ---------------------------------------------------


def test_symlinked_state_refused_before_minting(
    monkeypatch, tmp_path, clean_engine, mint_spy
):
    config = _config(tmp_path)
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"seed_credentials": {}}), encoding="utf-8")
    state = Path(config.state_path)
    state.parent.mkdir(parents=True)
    state.symlink_to(target)
    monkeypatch.setattr(run_seed, "_validate_existing_seed", lambda cfg: None)

    with pytest.raises(credential_output.UnsafeCredentialPathError):
        run_seed._seed_once(config)

    assert mint_spy == [], "keys were minted/rotated before the refusal"
    assert json.loads(target.read_text(encoding="utf-8")) == {"seed_credentials": {}}


def test_dangling_state_symlink_refused_before_seeding(
    monkeypatch, tmp_path, clean_engine, mint_spy
):
    config = _config(tmp_path)
    state = Path(config.state_path)
    state.parent.mkdir(parents=True)
    state.symlink_to(tmp_path / "does-not-exist.json")

    def _no_init(**kwargs):
        raise AssertionError("seeding started before the state path was checked")

    monkeypatch.setattr("api.db.init_db", _no_init)

    with pytest.raises(credential_output.UnsafeCredentialPathError):
        run_seed._seed_once(config)
    assert mint_spy == []
    assert not (tmp_path / "does-not-exist.json").exists()


# --- Atomic rewrite ----------------------------------------------------------


def test_interrupted_rewrite_keeps_previous_complete_state(
    monkeypatch, tmp_path, clean_engine, mint_spy
):
    """A rewrite that fails part-way (disk full, kill) must not leave a
    truncated file: that destroys the only copy of the current keys and makes
    every later run crash on unparseable JSON."""
    config = _config(tmp_path)
    state = _write_state(config, _OLD_KEYS)
    before = state.read_bytes()
    monkeypatch.setattr(run_seed, "_validate_existing_seed", lambda cfg: None)

    def _enospc(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(credential_output.os, "write", _enospc)

    with pytest.raises(OSError):
        run_seed._seed_once(config)

    assert state.read_bytes() == before
    assert sorted(p.name for p in state.parent.iterdir()) == [state.name], (
        "a partial temporary credential file was left behind"
    )


def test_rewrite_does_not_write_through_hardlink(tmp_path):
    state = tmp_path / "bootstrap_state.json"
    state.write_text(json.dumps({"seed_credentials": _OLD_KEYS}), encoding="utf-8")
    state.chmod(0o600)
    other = tmp_path / "linked-elsewhere.json"
    os.link(state, other)

    credential_output.write_private_text(
        state, json.dumps({"seed_credentials": _NEW_KEYS})
    )

    assert json.loads(other.read_text(encoding="utf-8")) == {
        "seed_credentials": _OLD_KEYS
    }
    assert json.loads(state.read_text(encoding="utf-8")) == {
        "seed_credentials": _NEW_KEYS
    }
    assert os.stat(state).st_nlink == 1


def test_successful_rewrite_is_private_and_complete(
    monkeypatch, tmp_path, clean_engine, mint_spy
):
    config = _config(tmp_path)
    state = _write_state(config, _OLD_KEYS)
    state.chmod(0o644)
    monkeypatch.setattr(run_seed, "_validate_existing_seed", lambda cfg: None)

    result = run_seed._seed_once(config)

    assert result["status"] == "already_seeded"
    assert _mode(state) == 0o600
    stored = json.loads(state.read_text(encoding="utf-8"))
    assert stored["seed_credentials"] == _NEW_KEYS  # tester hand-off intact
    assert sorted(p.name for p in state.parent.iterdir()) == [state.name]


def test_rewrite_refuses_unsafe_parent(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(credential_output.UnsafeCredentialPathError):
        credential_output.write_private_text(shared / "state.json", "{}")
    assert list(shared.iterdir()) == []


# --- Repository hygiene ------------------------------------------------------


def test_seed_state_is_never_tracked_by_git():
    tracked = subprocess.run(
        ["git", "ls-files", "--", "state"],
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert tracked == ""
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "state/seed/bootstrap_state.json"],
        cwd=_REPO,
    )
    assert ignored.returncode == 0, "seed state file is not git-ignored"
