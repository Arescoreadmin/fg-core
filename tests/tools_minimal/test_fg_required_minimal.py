from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.testing.harness import fg_required


class FgRequiredMinimalTests(unittest.TestCase):
    def test_lane_order_integrity(self) -> None:
        self.assertEqual(
            fg_required.LANES,
            (
                "policy-validate",
                "required-tests-gate",
                "fg-fast",
                "fg-contract",
                "fg-security",
            ),
        )

    def test_verify_required_files_detects_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(fg_required, "ARTIFACT_ROOT", Path(tmp)):
                with self.assertRaises(SystemExit):
                    fg_required._verify_required_files(
                        results=[], generated_reports=[], strict=True
                    )

    def test_redaction_is_value_based_and_json_safe(self) -> None:
        os.environ["FG_SECRET_TOKEN"] = "supersecret"
        secrets = fg_required._secret_values()
        line = (
            "FG_API_KEY=supersecret\n"
            "Authorization: Bearer eyJabc123\n"
            "password=hunter2\n"
            "token: abcdef\n"
            '{"api_key":"supersecret","token":"eyJ.jwt.token"}\n'
        )
        sanitized = fg_required._sanitize(line, secrets)
        self.assertIn("FG_API_KEY=[REDACTED]", sanitized)
        self.assertIn("Authorization: Bearer [REDACTED]", sanitized)
        self.assertIn("password=[REDACTED]", sanitized)
        self.assertIn("token: [REDACTED]", sanitized)
        self.assertIn('{"api_key":"[REDACTED]","token":"[REDACTED]"}', sanitized)
        self.assertNotIn("supersecret", sanitized)
        self.assertNotIn("eyJabc123", sanitized)
        self.assertNotIn("hunter2", sanitized)
        self.assertNotIn("abcdef", sanitized)

    def test_multiline_json_redaction_scope_documented(self) -> None:
        secrets = ["supersecret"]
        line = '{\n  "api_key":\n  "supersecret"\n}\n'
        sanitized = fg_required._sanitize(line, secrets)
        # Guarantee: same-line key/value redaction + value-based redaction for known secret values.
        self.assertIn('"api_key":', sanitized)
        self.assertIn("[REDACTED]", sanitized)

    def test_validate_lane_commands_rejects_disallowed(self) -> None:
        bad = dict(fg_required.LANE_COMMANDS)
        bad["fg-fast"] = (("printenv",),)
        with mock.patch.object(fg_required, "LANE_COMMANDS", bad):
            with self.assertRaises(SystemExit):
                fg_required._validate_lane_commands()

    def test_validate_lane_commands_rejects_dotenv_dump(self) -> None:
        bad = dict(fg_required.LANE_COMMANDS)
        bad["fg-fast"] = (("bash", "-lc", "cat .env"),)
        with mock.patch.object(fg_required, "LANE_COMMANDS", bad):
            with self.assertRaises(SystemExit):
                fg_required._validate_lane_commands()

    def test_summary_ui_shape_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(fg_required, "ARTIFACT_ROOT", root):
                for name in (
                    "required-tests-gate.json",
                    "contract-drift.json",
                    "security-invariants.json",
                ):
                    (root / name).write_text("{}\n", encoding="utf-8")
                hashes = {
                    name: fg_required._sha256(root / name)
                    for name in (
                        "required-tests-gate.json",
                        "contract-drift.json",
                        "security-invariants.json",
                    )
                }
                results = [
                    fg_required.LaneResult(
                        "policy-validate",
                        "passed",
                        1,
                        False,
                        artifact_paths={"lane_log": "a", "lane_triage": "b"},
                    ),
                ]
                fg_required._write_summary(results, "passed", 480, 12, hashes)
                payload = json.loads(
                    (root / "fg-required-summary.json").read_text(encoding="utf-8")
                )
                self.assertEqual(payload["overall_status"], "passed")
                self.assertEqual(payload["budget_seconds"], 480)
                self.assertEqual(payload["elapsed_seconds"], 12)
                self.assertIn("artifact_hashes", payload)
                self.assertEqual(payload["lanes"][0]["name"], "policy-validate")

    def test_budget_exceeded_mid_run_is_lane_aware(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(fg_required, "ARTIFACT_ROOT", root):
                with mock.patch.object(
                    fg_required, "_check_working_tree_clean", return_value=None
                ):
                    (root / "lanes" / "policy-validate").mkdir(
                        parents=True, exist_ok=True
                    )
                    (root / "lanes" / "policy-validate" / "lane.log").write_text(
                        "ok\n", encoding="utf-8"
                    )
                    (
                        root / "lanes" / "policy-validate" / "lane.triage.json"
                    ).write_text("{}\n", encoding="utf-8")
                    with mock.patch.object(
                        fg_required,
                        "_run_lane",
                        side_effect=[
                            fg_required.LaneResult(
                                "policy-validate",
                                "passed",
                                1,
                                False,
                                artifact_paths={
                                    "lane_log": str(
                                        root / "lanes/policy-validate/lane.log"
                                    ),
                                    "lane_triage": str(
                                        root / "lanes/policy-validate/lane.triage.json"
                                    ),
                                },
                            )
                        ],
                    ):
                        with mock.patch(
                            "time.monotonic", side_effect=[0.0, 1.0, 500.0, 501.0]
                        ):
                            argv = [
                                "fg_required.py",
                                "--global-budget-seconds",
                                "480",
                                "--strict",
                                "--dry-run",
                            ]
                            with mock.patch("sys.argv", argv):
                                rc = fg_required.main()
                self.assertEqual(rc, 1)
                self.assertTrue((root / "fg-required-summary.json").exists())
                self.assertTrue((root / "fg-required-summary.md").exists())
                self.assertTrue(
                    (root / "lanes" / "required-tests-gate" / "lane.log").exists()
                )
                self.assertTrue(
                    (
                        root / "lanes" / "required-tests-gate" / "lane.triage.json"
                    ).exists()
                )
                self.assertFalse((root / "contract-drift.json").exists())
                self.assertFalse((root / "security-invariants.json").exists())
                self.assertTrue((root / "required-tests-gate.json").exists())

    def test_blocked_command_is_path_aware(self) -> None:
        self.assertFalse(
            fg_required._is_blocked_command(
                ("python", "-c", 'print("docs/.env.example")')
            )
        )

    def test_working_tree_mutation_detected_after_lane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(fg_required, "ARTIFACT_ROOT", root):
                with mock.patch.object(
                    fg_required,
                    "_run_lane",
                    return_value=fg_required.LaneResult(
                        "policy-validate",
                        "passed",
                        1,
                        False,
                        artifact_paths={
                            "lane_log": str(root / "lanes/policy-validate/lane.log"),
                            "lane_triage": str(
                                root / "lanes/policy-validate/lane.triage.json"
                            ),
                        },
                    ),
                ):
                    (root / "lanes" / "policy-validate").mkdir(
                        parents=True, exist_ok=True
                    )
                    (root / "lanes" / "policy-validate" / "lane.log").write_text(
                        "ok\n", encoding="utf-8"
                    )
                    (
                        root / "lanes" / "policy-validate" / "lane.triage.json"
                    ).write_text("{}\n", encoding="utf-8")
                    with mock.patch.object(
                        fg_required,
                        "_check_working_tree_clean",
                        side_effect=[None, SystemExit("working tree mutated")],
                    ):
                        argv = [
                            "fg_required.py",
                            "--global-budget-seconds",
                            "480",
                            "--strict",
                            "--dry-run",
                        ]
                        with mock.patch("sys.argv", argv):
                            with self.assertRaises(SystemExit):
                                fg_required.main()

    def test_lane_failure_reason_not_masked_by_cleanliness_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(fg_required, "ARTIFACT_ROOT", root):
                lane_dir = root / "lanes" / "policy-validate"
                lane_dir.mkdir(parents=True, exist_ok=True)
                (lane_dir / "lane.log").write_text("fail\n", encoding="utf-8")
                (lane_dir / "lane.triage.json").write_text("{}\n", encoding="utf-8")
                failed = fg_required.LaneResult(
                    "policy-validate",
                    "failed",
                    1,
                    False,
                    error="exit_2",
                    artifact_paths={
                        "lane_log": str(lane_dir / "lane.log"),
                        "lane_triage": str(lane_dir / "lane.triage.json"),
                    },
                )
                with mock.patch.object(fg_required, "_run_lane", return_value=failed):
                    checker = mock.Mock(side_effect=[None])
                    with mock.patch.object(
                        fg_required, "_check_working_tree_clean", checker
                    ):
                        argv = [
                            "fg_required.py",
                            "--global-budget-seconds",
                            "480",
                            "--strict",
                            "--dry-run",
                        ]
                        with mock.patch("sys.argv", argv):
                            rc = fg_required.main()
                self.assertEqual(rc, 1)
                checker.assert_called_once_with("start")


if __name__ == "__main__":
    unittest.main()
