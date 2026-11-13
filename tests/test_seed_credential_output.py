"""CODEQL-REMEDIATE-003 — seed tooling must not print live credentials.

CodeQL #31 (``tools/seed/demo_tenants.py``) and #52 (``tools/seed/run_seed.py``)
flag ``print()`` of a result dict that carries freshly minted credentials:

- demo_tenants: production demo-tenant API keys
  (``demo_tenant_api_key_map_json``) and portal passwords, re-minted on every
  run;
- run_seed: local seed API keys (``seed_credentials``, ``ag_core_api_key``).

Stdout lands in terminal scrollback, CI/agent transcripts and log collectors.
Credentials must go only to an owner-only (0600) file; stdout carries an
allowlisted, credential-free summary that points at that file.

All values below are synthetic.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from tools.seed import demo_tenants, run_seed

_API_KEY = "fgk.synthetic-demo-key-" + "A" * 24
_PORTAL_PW = "synthetic-portal-pw-" + "B" * 20
_FUTURE = "synthetic-future-secret-" + "C" * 16
_SEED_KEYS = {
    "admin_api_key": "fgk.synthetic-admin-" + "D" * 20,
    "agent_api_key": "fgk.synthetic-agent-" + "E" * 20,
    "audit_api_key": "fgk.synthetic-audit-" + "F" * 20,
}


def _demo_result() -> dict:
    return {
        "generated_at": "2026-11-13T00:00:00Z",
        "portal_demo_tenants": "demo-bank",
        "console_demo_tenants": "demo-bank",
        "tenants": [
            {
                "tenant_id": "demo-bank",
                "tenant_label": "Demo Bank",
                "client_name": "Demo Bank Client",
                "sector": "banking",
                "assessment_type": "field",
                "engagement_id": "eng-1",
                "report_id": "rep-1",
                "status": "delivered",
                "api_key_status": "created",
                "portal_username": "demo-bank-user",
                "portal_password": _PORTAL_PW,
                "portal_grant_id": "grant-1",
                "portal_grant_expires_at": "2027-11-13T00:00:00Z",
                "portal_url": "https://app.frostgate.ai/login?tenant_id=demo-bank",
                "console_url": "https://console.frostgate.ai/field-assessment/eng-1",
                # A field added later must not reach stdout by default.
                "future_field": _FUTURE,
            }
        ],
        "demo_tenant_api_key_map_json": json.dumps({"demo-bank": _API_KEY}),
        "demo_tenant_api_key_note": "Update FG_PORTAL_DEMO_TENANT_KEYS in Vercel.",
    }


@pytest.fixture
def fake_seed(monkeypatch):
    calls: list[dict] = []

    def _seed(*, dry_run: bool, rotate_keys: bool = False) -> dict:
        calls.append({"dry_run": dry_run, "rotate_keys": rotate_keys})
        return {"dry_run": True} if dry_run else _demo_result()

    monkeypatch.setattr(demo_tenants, "seed", _seed)
    return calls


def _run_demo(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["demo_tenants.py", *argv])
    return demo_tenants.main()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# --- demo_tenants (#31) -----------------------------------------------------


def test_demo_stdout_has_no_credentials(monkeypatch, capsys, tmp_path, fake_seed):
    out = tmp_path / "creds.json"
    assert _run_demo(monkeypatch, "--output", str(out)) == 0

    printed = capsys.readouterr()
    for secret in (_API_KEY, _PORTAL_PW, _FUTURE):
        assert secret not in printed.out
        assert secret not in printed.err


def test_demo_stdout_keeps_operator_summary(monkeypatch, capsys, tmp_path, fake_seed):
    out = tmp_path / "creds.json"
    _run_demo(monkeypatch, "--output", str(out))

    summary = json.loads(capsys.readouterr().out)
    assert summary["credentials_file"] == str(out)
    (tenant,) = summary["tenants"]
    assert tenant["tenant_id"] == "demo-bank"
    assert tenant["api_key_status"] == "created"
    assert tenant["portal_grant_id"] == "grant-1"
    assert summary["api_key_issued_tenants"] == ["demo-bank"]
    assert "portal_password" not in tenant
    assert "demo_tenant_api_key_map_json" not in summary


def test_demo_credentials_file_is_complete_and_owner_only(
    monkeypatch, capsys, tmp_path, fake_seed
):
    old = os.umask(0o022)
    try:
        out = tmp_path / "creds.json"
        _run_demo(monkeypatch, "--output", str(out))
    finally:
        os.umask(old)

    assert _mode(out) == 0o600
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written == _demo_result()  # operator handoff content unchanged


def test_demo_refuses_to_overwrite_existing_file(
    monkeypatch, capsys, tmp_path, fake_seed
):
    out = tmp_path / "creds.json"
    out.write_text("operator notes", encoding="utf-8")

    assert _run_demo(monkeypatch, "--output", str(out)) == 2
    assert out.read_text(encoding="utf-8") == "operator notes"
    assert fake_seed == []  # failed before minting anything


def test_demo_output_refuses_symlink(monkeypatch, capsys, tmp_path, fake_seed):
    target = tmp_path / "elsewhere.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "creds.json"
    link.symlink_to(target)

    assert _run_demo(monkeypatch, "--output", str(link)) == 2
    assert target.read_text(encoding="utf-8") == "{}"
    assert fake_seed == []


def test_demo_output_refuses_dangling_symlink(monkeypatch, capsys, tmp_path, fake_seed):
    link = tmp_path / "creds.json"
    link.symlink_to(tmp_path / "not-yet-created.json")

    assert _run_demo(monkeypatch, "--output", str(link)) == 2
    assert not (tmp_path / "not-yet-created.json").exists()
    assert fake_seed == []


def test_demo_refuses_world_writable_parent(monkeypatch, capsys, tmp_path, fake_seed):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)  # writable by others, no sticky bit

    assert _run_demo(monkeypatch, "--output", str(shared / "creds.json")) == 2
    assert "writable by other users" in capsys.readouterr().err
    assert not (shared / "creds.json").exists()
    assert fake_seed == []


def test_demo_refuses_symlinked_parent(monkeypatch, capsys, tmp_path, fake_seed):
    real = tmp_path / "real"
    real.mkdir()
    via = tmp_path / "via"
    via.symlink_to(real, target_is_directory=True)

    assert _run_demo(monkeypatch, "--output", str(via / "creds.json")) == 2
    assert not (real / "creds.json").exists()
    assert fake_seed == []


def test_demo_seed_failure_withholds_exception_text(monkeypatch, capsys, tmp_path):
    def _boom(*, dry_run: bool, rotate_keys: bool = False) -> dict:
        raise RuntimeError(f"insert failed: params=({_API_KEY!r}, {_PORTAL_PW!r})")

    monkeypatch.setattr(demo_tenants, "seed", _boom)
    out = tmp_path / "creds.json"

    assert _run_demo(monkeypatch, "--output", str(out)) == 3
    printed = capsys.readouterr()
    assert _API_KEY not in printed.out + printed.err
    assert _PORTAL_PW not in printed.out + printed.err
    assert "RuntimeError" in printed.err
    assert "--rotate-keys" in printed.err  # recovery path
    assert not out.exists()


def test_demo_write_failure_after_minting_gives_recovery(
    monkeypatch, capsys, tmp_path, fake_seed
):
    def _enospc(fd: int, text: str) -> None:
        os.close(fd)
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(demo_tenants, "write_fd_text", _enospc)
    out = tmp_path / "creds.json"

    assert _run_demo(monkeypatch, "--output", str(out)) == 4
    printed = capsys.readouterr()
    for secret in (_API_KEY, _PORTAL_PW, _FUTURE):
        assert secret not in printed.out + printed.err
    assert "demo-bank" in printed.err  # which tenants need recovery
    assert "--rotate-keys" in printed.err
    assert printed.out == ""  # no success summary
    assert not out.exists()  # no partial credential file left behind


def test_demo_without_output_fails_before_minting(monkeypatch, capsys, fake_seed):
    rc = _run_demo(monkeypatch)

    assert rc != 0
    assert fake_seed == []  # no keys rotated, no portal grants revoked
    printed = capsys.readouterr()
    assert "--output" in printed.err
    assert _API_KEY not in printed.out + printed.err


def test_demo_dry_run_without_output_still_works(monkeypatch, capsys, fake_seed):
    assert _run_demo(monkeypatch, "--dry-run") == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True
    assert fake_seed == [{"dry_run": True, "rotate_keys": False}]


# --- run_seed (#52) -----------------------------------------------------------


def _seed_payload(state_path: Path) -> dict:
    return {
        "export_path": "state/seed/export.zip",
        "registry_path": "state/tenants.json",
        "session_id": "cycle-synthetic-1",
        "sqlite_path": "state/frostgate.db",
        "tenant_id": "tenant-seed-primary",
        "seed_credentials": dict(_SEED_KEYS),
        "seed_credential_status": {"admin": "issued", "agent": "issued"},
        "ag_core_api_key": _SEED_KEYS["audit_api_key"],
        "status": "seeded",
    }


def _config(tmp_path: Path) -> run_seed.SeedConfig:
    return run_seed.SeedConfig(
        sqlite_path=str(tmp_path / "frostgate.db"),
        registry_path=str(tmp_path / "tenants.json"),
        state_path=str(tmp_path / "seed" / "bootstrap_state.json"),
        tenant_id="tenant-seed-primary",
    )


def test_run_seed_stdout_has_no_credentials(monkeypatch, capsys, tmp_path):
    config = _config(tmp_path)
    monkeypatch.setattr(run_seed, "_set_default_env", lambda: config)
    monkeypatch.setattr(
        run_seed, "_seed_once", lambda cfg: _seed_payload(Path(cfg.state_path))
    )

    assert run_seed._internal_main() == 0

    printed = capsys.readouterr()
    for secret in _SEED_KEYS.values():
        assert secret not in printed.out
        assert secret not in printed.err
    summary = json.loads(printed.out)
    assert summary["status"] == "seeded"
    assert summary["session_id"] == "cycle-synthetic-1"
    assert summary["export_path"] == "state/seed/export.zip"
    assert summary["seed_credential_status"] == {"admin": "issued", "agent": "issued"}
    assert summary["credentials_file"] == config.state_path


def test_run_seed_state_file_is_owner_only(monkeypatch, tmp_path):
    config = _config(tmp_path)
    state = Path(config.state_path)
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps(_seed_payload(state)), encoding="utf-8")
    state.chmod(0o644)
    monkeypatch.setattr(run_seed, "_validate_existing_seed", lambda cfg: None)
    monkeypatch.setattr(
        run_seed, "_ensure_seed_credentials", lambda cfg, payload: payload
    )

    result = run_seed._seed_once(config)

    assert result["status"] == "already_seeded"
    assert _mode(state) == 0o600
    # Documented tester flow reads keys from the state file: still there.
    stored = json.loads(state.read_text(encoding="utf-8"))
    assert stored["seed_credentials"] == _SEED_KEYS


def test_run_seed_state_file_refuses_symlink(monkeypatch, tmp_path):
    config = _config(tmp_path)
    state = Path(config.state_path)
    state.parent.mkdir(parents=True)
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps(_seed_payload(state)), encoding="utf-8")
    state.symlink_to(target)
    monkeypatch.setattr(run_seed, "_validate_existing_seed", lambda cfg: None)
    monkeypatch.setattr(
        run_seed, "_ensure_seed_credentials", lambda cfg, payload: payload
    )

    with pytest.raises(OSError):
        run_seed._seed_once(config)
    assert json.loads(target.read_text(encoding="utf-8"))["status"] == "seeded"


def test_demo_accepts_own_private_group_writable_parent(
    monkeypatch, capsys, tmp_path, fake_seed
):
    # umask 0002 with a user-private group (common Linux default).
    mine = tmp_path / "mine"
    mine.mkdir()
    mine.chmod(0o770)
    assert mine.stat().st_gid == os.getgid()
    out = mine / "creds.json"

    assert _run_demo(monkeypatch, "--output", str(out)) == 0
    assert _mode(out) == 0o600
