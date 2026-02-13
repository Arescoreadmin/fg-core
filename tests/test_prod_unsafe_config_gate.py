from __future__ import annotations


import tools.ci.check_prod_unsafe_config as gate


def test_gate_fails_on_forbidden_contract_gen_flag_in_prod_like(
    tmp_path, monkeypatch, capsys
):
    # prod-like because path is docker-compose.yml
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """
services:
  frostgate-core:
    environment:
      FG_DB_URL: "postgresql://example"
      FG_CONTRACT_GEN_CONTEXT: "true"
""",
        encoding="utf-8",
    )

    # Point gate to our temp file only
    monkeypatch.setattr(gate, "FILES", [compose])

    rc = gate.main()
    out = capsys.readouterr().out.lower()

    assert rc == 1
    assert "failed" in out
    assert "fg_contract_gen_context=true is forbidden" in out


def test_gate_fails_on_forbidden_marker_in_prod_like(tmp_path, monkeypatch, capsys):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """
# Contract generation context detected: allowing missing OIDC configuration
services:
  frostgate-core:
    environment:
      FG_DB_URL: "postgresql://example"
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(gate, "FILES", [compose])

    rc = gate.main()
    out = capsys.readouterr().out.lower()

    assert rc == 1
    assert "failed" in out
    assert "forbidden marker present" in out


def test_gate_passes_on_clean_prod_like_manifest(tmp_path, monkeypatch, capsys):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """
services:
  frostgate-core:
    environment:
      FG_DB_URL: "postgresql://example"
      FG_AUTH_ALLOW_FALLBACK: "false"
      FG_RL_FAIL_OPEN: "false"
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(gate, "FILES", [compose])

    rc = gate.main()
    out = capsys.readouterr().out.lower()

    assert rc == 0
    assert "ok" in out
