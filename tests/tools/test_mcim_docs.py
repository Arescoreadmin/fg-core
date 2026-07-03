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
