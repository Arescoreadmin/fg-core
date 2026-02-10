from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow importing gate script from scripts/
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from verify_bp_d_000 import run_gate


ALIGN_OK = '{"BP-D-000": "make bp-d-000-gate"}\n'


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _minimal_repo(tmp_path: Path) -> None:
    _write(tmp_path / "tools" / "align_score_map.json", ALIGN_OK)
    _write(tmp_path / "ui" / "theme.css", ":root { --brand: #112233; }\n")
    _write(tmp_path / "brand" / "BRAND.json", '{"tokens": {"primary": "#112233"}}\n')


def _report(tmp_path: Path) -> dict[str, object]:
    report_path = tmp_path / "artifacts" / "gates" / "bp_d_000_report.json"
    return json.loads(report_path.read_text(encoding="utf-8"))


def test_pass_hex_in_theme_css_allowed(tmp_path: Path) -> None:
    _minimal_repo(tmp_path)
    _write(tmp_path / "ui" / "components" / "Button.tsx", "export const x = 'ok';\n")

    code, report = run_gate(tmp_path)

    assert code == 0
    assert report["passed"] is True
    assert report["findings"] == []


def test_pass_hex_in_brand_json_allowed(tmp_path: Path) -> None:
    _minimal_repo(tmp_path)
    _write(tmp_path / "dashboard" / "App.tsx", "export const App = () => null;\n")

    code, report = run_gate(tmp_path)

    assert code == 0
    assert report["passed"] is True


def test_fail_hex_in_ui_component(tmp_path: Path) -> None:
    _minimal_repo(tmp_path)
    _write(
        tmp_path / "ui" / "components" / "Button.tsx",
        "const style = { color: '#abc' };\n",
    )

    code, report = run_gate(tmp_path)

    assert code == 1
    assert report["passed"] is False
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["file"] == "ui/components/Button.tsx"
    assert finding["line"] == 1
    assert finding["type"] == "hex"


def test_fail_rgb_in_ui_file(tmp_path: Path) -> None:
    _minimal_repo(tmp_path)
    _write(tmp_path / "frontend" / "styles.css", ".x { color: rgb(10, 20, 30); }\n")

    code, report = run_gate(tmp_path)

    assert code == 1
    assert report["findings"][0]["type"] == "rgb"


def test_fail_hsl_in_ui_file(tmp_path: Path) -> None:
    _minimal_repo(tmp_path)
    _write(
        tmp_path / "dashboard" / "styles.scss", ".x { color: hsl(120, 100%, 50%); }\n"
    )

    code, report = run_gate(tmp_path)

    assert code == 1
    assert report["findings"][0]["type"] == "hsl"


def test_fail_missing_theme_css(tmp_path: Path) -> None:
    _write(tmp_path / "tools" / "align_score_map.json", ALIGN_OK)
    _write(tmp_path / "brand" / "BRAND.json", '{"tokens": {"primary": "#112233"}}\n')

    code, report = run_gate(tmp_path)

    assert code == 1
    assert any("ui/theme.css" in err for err in report["errors"])


def test_fail_missing_align_score_map(tmp_path: Path) -> None:
    _write(tmp_path / "ui" / "theme.css", ":root {}\n")
    _write(tmp_path / "brand" / "BRAND.json", '{"tokens": {"primary": "#112233"}}\n')

    code, report = run_gate(tmp_path)

    assert code == 1
    assert any("align_score_map.json" in err for err in report["errors"])


def test_fail_align_score_mismatch(tmp_path: Path) -> None:
    _write(tmp_path / "tools" / "align_score_map.json", '{"BP-D-000": "wrong"}\n')
    _write(tmp_path / "ui" / "theme.css", ":root {}\n")
    _write(tmp_path / "brand" / "BRAND.json", '{"tokens": {"primary": "#112233"}}\n')

    code, report = run_gate(tmp_path)

    assert code == 1
    assert any("expected 'make bp-d-000-gate'" in err for err in report["errors"])


def test_report_keys_exactly_specified(tmp_path: Path) -> None:
    _minimal_repo(tmp_path)

    run_gate(tmp_path)
    report = _report(tmp_path)

    assert set(report.keys()) == {
        "gate_id",
        "passed",
        "generated_at_utc",
        "invariant",
        "checked_files",
        "files_scanned",
        "findings",
        "errors",
    }


def test_findings_not_truncated(tmp_path: Path) -> None:
    _minimal_repo(tmp_path)
    _write(
        tmp_path / "ui" / "components" / "Palette.tsx",
        "\n".join(
            [
                "const a = '#111';",
                "const b = '#222';",
                "const c = 'rgb(1,2,3)';",
                "const d = 'hsl(1,2%,3%)';",
            ]
        )
        + "\n",
    )

    code, report = run_gate(tmp_path)

    assert code == 1
    assert len(report["findings"]) == 4
