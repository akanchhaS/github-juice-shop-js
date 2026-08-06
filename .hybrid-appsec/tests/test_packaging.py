import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PACKAGE_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "bin"))

from fetch_ghas_alerts import fetch_alerts  # noqa: E402
from github_code_scanning import build_plan  # noqa: E402


class PackagingTest(unittest.TestCase):
    def test_pinned_target_and_codex_adapter_are_consistent(self):
        target = json.loads(
            (PACKAGE_ROOT / "fixtures/target-profile.juice-shop.json").read_text()
        )
        codex = json.loads(
            (PACKAGE_ROOT / "fixtures/codex-security-juice-shop.sample.json").read_text()
        )
        self.assertEqual(target["repository"], "Assume/github-juice-shop-js")
        self.assertEqual(
            target["commit"], "c4bea13c8712e01606947b58552d20f8f5e05319"
        )
        self.assertEqual(
            sum(item["status"] == "reportable" for item in codex["findings"]), 9
        )
        self.assertEqual(
            sum(item["status"] == "candidate" for item in codex["findings"]), 1
        )

    def test_all_codeql_states_are_included_in_repeat_runs(self):
        def fake_fetch(url, token):
            if "page=2" in url:
                return []
            if "state=open" in url:
                return [{"number": 3, "state": "open"}]
            if "state=dismissed" in url:
                return [{"number": 2, "state": "dismissed"}]
            if "state=fixed" in url:
                return [{"number": 1, "state": "fixed"}]
            self.fail(f"unexpected URL: {url}")

        with patch("fetch_ghas_alerts.fetch_json", side_effect=fake_fetch):
            alerts = fetch_alerts(
                "Assume/github-juice-shop-js",
                "mock-token",
                state=None,
                tool_name="CodeQL",
            )
        self.assertEqual([alert["number"] for alert in alerts], [1, 2, 3])

    def test_plan_is_non_mutating_and_excludes_closed_false_positives(self):
        triage = {
            "findings": [
                {
                    "input_id": "ghas-alert-7",
                    "verdict": "not_actionable",
                    "normalized_input": {
                        "affected_version_or_path": "abc123:app.js",
                        "scanner_state": "dismissed",
                    },
                    "counterevidence": ["Already reviewed."],
                }
            ]
        }
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = Path(tmp) / "upload.sarif"
            sarif_path.write_text(json.dumps(sarif))
            plan = build_plan(
                triage,
                sarif_path,
                "Assume/github-juice-shop-js",
                "abc123",
                "refs/heads/master",
            )
        self.assertEqual(plan["dismissals"], [])
        self.assertEqual(plan["safety"]["default_mode"], "plan")


if __name__ == "__main__":
    unittest.main()
