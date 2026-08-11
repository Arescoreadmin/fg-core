from tools.ci.check_mcim_docs import (
    REQUIRED_DOCS,
    REQUIRED_JSON_BLOCKS,
    extract_named_json_blocks,
    repo_root,
    run_checks,
    validate_required_sections,
)


def test_required_docs_exist() -> None:
    root = repo_root()
    for rel in REQUIRED_DOCS:
        assert (root / rel).is_file(), rel


def test_master_doc_has_required_sections() -> None:
    root = repo_root()
    text = (root / REQUIRED_DOCS[0]).read_text(encoding="utf-8")
    assert validate_required_sections(text) == []


def test_machine_readable_blocks_exist_and_parse() -> None:
    root = repo_root()
    text = (root / REQUIRED_DOCS[0]).read_text(encoding="utf-8")
    blocks = extract_named_json_blocks(text)
    assert set(REQUIRED_JSON_BLOCKS).issubset(blocks.keys())
    for name, raw in blocks.items():
        assert raw.strip(), name


def test_full_mcim_check_passes() -> None:
    root = repo_root()
    assert run_checks(root) == []


def test_seed_bootstrap_docs_use_canonical_generated_credentials() -> None:
    from tools.seed import run_seed

    root = repo_root()
    quickstart = (root / "docs/tester_quickstart.md").read_text(encoding="utf-8")
    collection = (root / "docs/tester_collection.json").read_text(encoding="utf-8")

    assert run_seed.DEFAULT_KEY_PEPPER in quickstart
    assert "seed_credentials.audit_api_key" in quickstart
    assert "seed_credentials']['audit_api_key" in collection
    assert "seedauditgwkey0_000000000000" not in quickstart
    assert "mint_key('audit:read'" not in collection
