from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


IMPLEMENTED_GATES = (
    "BP-S0-001",
    "BP-S0-005",
    "BP-C-005",
    "BP-C-006",
    "BP-M1-006",
    "BP-M2-001",
    "BP-M2-002",
    "BP-M2-003",
    "BP-M3-001",
    "BP-M3-003",
    "BP-M3-004",
    "BP-M3-005",
    "BP-M3-006",
    "BP-M3-007",
)


def _load_pairs(path: Path) -> list[tuple[str, str]]:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=list)


def test_align_score_map_has_no_duplicate_keys() -> None:
    pairs = _load_pairs(Path("tools/align_score_map.json"))
    keys = [k for k, _ in pairs]
    duplicates = [k for k, count in Counter(keys).items() if count > 1]
    assert duplicates == []


def test_implemented_gates_are_mapped_to_make_targets() -> None:
    mapping = dict(_load_pairs(Path("tools/align_score_map.json")))
    for gate_id in IMPLEMENTED_GATES:
        assert gate_id in mapping
        assert mapping[gate_id] != "MISSING"
        assert mapping[gate_id].startswith("make ")


def test_align_score_map_has_no_missing_placeholders() -> None:
    pairs = _load_pairs(Path("tools/align_score_map.json"))
    missing_keys = [key for key, value in pairs if value == "MISSING"]
    assert missing_keys == []
