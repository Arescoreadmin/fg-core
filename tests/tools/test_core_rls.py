from __future__ import annotations

from tools.ci import check_core_rls


# ---------------------------------------------------------------------------
# _is_excluded
# ---------------------------------------------------------------------------


def test_fa_tables_are_excluded():
    assert check_core_rls._is_excluded("fa_engagements")
    assert check_core_rls._is_excluded("fa_scan_results")
    assert check_core_rls._is_excluded("fa_field_observations")


def test_agent_phase2_tables_are_excluded():
    for t in check_core_rls._AGENT_PHASE2_TABLES:
        assert check_core_rls._is_excluded(t), f"expected {t} to be excluded"


def test_connector_tables_are_excluded():
    for t in check_core_rls._CONNECTOR_TABLES:
        assert check_core_rls._is_excluded(t), f"expected {t} to be excluded"


def test_nonstandard_policy_tables_are_excluded():
    for t in check_core_rls._NONSTANDARD_POLICY_TABLES:
        assert check_core_rls._is_excluded(t), f"expected {t} to be excluded"


def test_regular_table_not_excluded():
    assert not check_core_rls._is_excluded("billing_devices")
    assert not check_core_rls._is_excluded("reports")
    assert not check_core_rls._is_excluded("rag_corpora")


# ---------------------------------------------------------------------------
# main() integration — passes on actual migrations
# ---------------------------------------------------------------------------


def test_main_passes_on_actual_migrations():
    result = check_core_rls.main()
    assert result == 0, "check_core_rls.main() must pass after migration 0110"


# ---------------------------------------------------------------------------
# main() hard-fails when a table lacks RLS enable
# ---------------------------------------------------------------------------


def test_main_fails_on_missing_rls_enable(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_table.sql").write_text(
        "CREATE TABLE IF NOT EXISTS foo (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 1


def test_main_fails_on_missing_policy(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_table.sql").write_text(
        "CREATE TABLE IF NOT EXISTS bar (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE bar ENABLE ROW LEVEL SECURITY;\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 1


def test_main_passes_with_full_rls_coverage(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_table.sql").write_text(
        "CREATE TABLE IF NOT EXISTS baz (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE baz ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY baz_tenant_isolation ON baz USING (tenant_id = current_setting('app.tenant_id', true));\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 0


def test_main_passes_when_table_has_no_tenant_id(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_table.sql").write_text(
        "CREATE TABLE IF NOT EXISTS global_config (key TEXT PRIMARY KEY, value TEXT);\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 0


def test_main_excludes_fa_tables(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    # fa_ table with no RLS — should be excluded (covered by 0094/0095 dynamic migration)
    (sql_dir / "0001_table.sql").write_text(
        "CREATE TABLE IF NOT EXISTS fa_engagements (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 0


def test_main_reports_both_enable_and_policy_missing(tmp_path, monkeypatch, capsys):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_table.sql").write_text(
        "CREATE TABLE IF NOT EXISTS no_rls_table (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    result = check_core_rls.main()
    captured = capsys.readouterr()
    assert result == 1
    assert "RLS_ENABLE_MISSING" in captured.out
    assert "RLS_POLICY_MISSING" in captured.out


# ---------------------------------------------------------------------------
# P2: DISABLE / DROP regression detection
# ---------------------------------------------------------------------------


def test_later_disable_rls_is_caught(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_setup.sql").write_text(
        "CREATE TABLE IF NOT EXISTS tbl (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE tbl ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY tbl_tenant_isolation ON tbl USING (tenant_id = current_setting('app.tenant_id', true));\n"
    )
    (sql_dir / "0002_regression.sql").write_text(
        "ALTER TABLE tbl DISABLE ROW LEVEL SECURITY;\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 1


def test_drop_policy_without_recreate_is_caught(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_setup.sql").write_text(
        "CREATE TABLE IF NOT EXISTS tbl (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE tbl ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY tbl_tenant_isolation ON tbl USING (tenant_id = current_setting('app.tenant_id', true));\n"
    )
    (sql_dir / "0002_regression.sql").write_text(
        "DROP POLICY IF EXISTS tbl_tenant_isolation ON tbl;\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 1


def test_drop_then_recreate_in_same_file_is_ok(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_setup.sql").write_text(
        "CREATE TABLE IF NOT EXISTS tbl (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE tbl ENABLE ROW LEVEL SECURITY;\n"
        "DROP POLICY IF EXISTS tbl_tenant_isolation ON tbl;\n"
        "CREATE POLICY tbl_tenant_isolation ON tbl USING (tenant_id = current_setting('app.tenant_id', true));\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 0


def test_disable_then_reenable_in_same_file_is_ok(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_setup.sql").write_text(
        "CREATE TABLE IF NOT EXISTS tbl (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE tbl DISABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE tbl ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY tbl_tenant_isolation ON tbl USING (tenant_id = current_setting('app.tenant_id', true));\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 0


# ---------------------------------------------------------------------------
# Migration 0110 coverage assertion
# ---------------------------------------------------------------------------


def test_migration_0110_covers_billing_tables():
    sql = (
        check_core_rls.MIGRATIONS_DIR / "0110_core_tenant_rls_hardening.sql"
    ).read_text()
    critical = [
        "billing_devices",
        "billing_invoices",
        "billing_runs",
        "billing_credit_notes",
    ]
    for table in critical:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql, (
            f"{table} missing from migration 0110"
        )
        assert f"CREATE POLICY {table}_tenant_isolation" in sql, (
            f"{table} missing tenant_isolation policy in migration 0110"
        )


def test_migration_0110_covers_agent_tables():
    sql = (
        check_core_rls.MIGRATIONS_DIR / "0110_core_tenant_rls_hardening.sql"
    ).read_text()
    tables = ["agent_enrollment_tokens", "agent_device_keys", "agent_device_registry"]
    for table in tables:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql, (
            f"{table} missing from migration 0110"
        )


def test_migration_0110_covers_rag_tables():
    sql = (
        check_core_rls.MIGRATIONS_DIR / "0110_core_tenant_rls_hardening.sql"
    ).read_text()
    for table in ("rag_corpora", "rag_chunks", "rag_documents", "embedding_vectors"):
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql, (
            f"{table} missing from migration 0110"
        )


def test_migration_0110_covers_evaluation_and_timeline_policy_gaps():
    sql = (
        check_core_rls.MIGRATIONS_DIR / "0110_core_tenant_rls_hardening.sql"
    ).read_text()
    for table in (
        "evaluation_query_items",
        "evaluation_query_sets",
        "governance_timeline_events",
    ):
        assert f"CREATE POLICY {table}_tenant_isolation" in sql, (
            f"{table} missing tenant_isolation policy in migration 0110"
        )


# ---------------------------------------------------------------------------
# P3: Wrong GUC name detection (app.current_tenant_id must not appear)
# ---------------------------------------------------------------------------


def test_wrong_guc_in_new_migration_is_caught(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_setup.sql").write_text(
        "CREATE TABLE IF NOT EXISTS tbl (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE tbl ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY tbl_tenant_isolation ON tbl USING (tenant_id = current_setting('app.current_tenant_id', true));\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 1


def test_wrong_guc_in_plpgsql_execute_string_is_caught(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_setup.sql").write_text(
        "CREATE TABLE IF NOT EXISTS tbl (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE tbl ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY tbl_tenant_isolation ON tbl USING (tenant_id = current_setting('app.tenant_id', true));\n"
    )
    # New migration with the wrong GUC inside a PL/pgSQL EXECUTE string.
    (sql_dir / "0002_regression.sql").write_text(
        "DO $$ BEGIN\n"
        "  EXECUTE 'CREATE POLICY bad_policy ON tbl USING (tenant_id = current_setting(''app.current_tenant_id'', true))';\n"
        "END $$;\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 1


def test_wrong_guc_in_comment_is_not_flagged(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    (sql_dir / "0001_setup.sql").write_text(
        "-- Fixes policies that used app.current_tenant_id (wrong GUC).\n"
        "CREATE TABLE IF NOT EXISTS tbl (id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
        "ALTER TABLE tbl ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY tbl_tenant_isolation ON tbl USING (tenant_id = current_setting('app.tenant_id', true));\n"
    )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 0


def test_legacy_guc_patched_migrations_are_exempt(tmp_path, monkeypatch):
    sql_dir = tmp_path / "postgres"
    sql_dir.mkdir()
    for fname in check_core_rls._LEGACY_GUC_PATCHED_MIGRATIONS:
        (sql_dir / fname).write_text(
            "CREATE TABLE IF NOT EXISTS fa_tbl (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL);\n"
            "CREATE POLICY fa_tbl_tenant_isolation ON fa_tbl USING (tenant_id = current_setting('app.current_tenant_id', true));\n"
        )
    monkeypatch.setattr(check_core_rls, "MIGRATIONS_DIR", sql_dir)
    assert check_core_rls.main() == 0


# ---------------------------------------------------------------------------
# Migration 0111 coverage assertion
# ---------------------------------------------------------------------------


def test_migration_0111_drops_abbreviated_policy_names():
    sql = (
        check_core_rls.MIGRATIONS_DIR / "0111_fa_rls_guc_authority_alignment.sql"
    ).read_text()
    for policy in (
        "fa_tis_tenant_isolation",
        "fa_til_tenant_isolation",
        "fa_tdm_tenant_isolation",
        "fa_app_tenant_isolation",
        "fa_tc_tenant_isolation",
        "fa_drr_tenant_isolation",
        "fa_cocr_tenant_isolation",
    ):
        assert f"DROP POLICY IF EXISTS {policy}" in sql, (
            f"0111 missing DROP for {policy}"
        )


def test_migration_0111_uses_correct_guc():
    sql = (
        check_core_rls.MIGRATIONS_DIR / "0111_fa_rls_guc_authority_alignment.sql"
    ).read_text()
    import re

    sql_code = re.sub(r"--[^\n]*", "", sql)
    assert "app.current_tenant_id" not in sql_code, (
        "0111 must not reference app.current_tenant_id in executable SQL"
    )
    assert "app.tenant_id" in sql_code, "0111 must reference app.tenant_id"
