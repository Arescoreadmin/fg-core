from __future__ import annotations

import unittest
from unittest import mock

from tools.testing.harness import required_tests_gate


class RequiredTestsGateResolutionTests(unittest.TestCase):
    def test_resolve_diff_range_fallback_chain(self) -> None:
        calls = []

        def fake_run(args):
            calls.append(tuple(args))
            cmd = " ".join(args)
            if "merge-base origin/main HEAD" in cmd:
                return mock.Mock(returncode=1, stdout="")
            if "merge-base main HEAD" in cmd:
                return mock.Mock(returncode=0, stdout="abc123\n")
            return mock.Mock(returncode=0, stdout="")

        with mock.patch.object(required_tests_gate, "_run_git", side_effect=fake_run):
            base, head = required_tests_gate._resolve_diff_range(
                base_ref=None, base_sha=None, head_sha=None
            )
        self.assertEqual(base, "abc123")
        self.assertEqual(head, "HEAD")
        self.assertIn(("git", "merge-base", "origin/main", "HEAD"), calls)
        self.assertIn(("git", "merge-base", "main", "HEAD"), calls)


if __name__ == "__main__":
    unittest.main()
