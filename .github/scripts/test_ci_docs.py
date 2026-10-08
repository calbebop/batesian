import copy
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def documented_filter(path, filename):
    content = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(r"jq -e '([^']*)'\s+" + re.escape(filename), content)
    if match is None:
        raise AssertionError(f"missing jq filter for {filename} in {path}")
    return match.group(1)


def accepts(filter_text, report):
    result = subprocess.run(
        ["jq", "-e", filter_text],
        input=json.dumps(report),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode not in (0, 1, 4):
        raise AssertionError(result.stderr)
    return result.returncode == 0


class CIDocumentationTests(unittest.TestCase):
    def test_sarif_coverage_filters(self):
        complete = {
            "runs": [{
                "invocations": [{
                    "executionSuccessful": True,
                    "properties": {
                        "rulesSelected": 2,
                        "rulesCompleted": 2,
                        "rulesSkipped": 0,
                        "rulesErrored": 0,
                    },
                }],
            }],
        }
        cases = {"complete": complete, "no runs": {"runs": []},
                 "v1.7.0": {"runs": [{"results": []}]}}
        for name, changes in (
            ("no selected rules", {"rulesSelected": 0, "rulesCompleted": 0}),
            ("skipped rule", {"rulesCompleted": 1, "rulesSkipped": 1}),
            ("errored rule", {"rulesCompleted": 1, "rulesErrored": 1}),
        ):
            report = copy.deepcopy(complete)
            report["runs"][0]["invocations"][0]["properties"].update(changes)
            cases[name] = report
        report = copy.deepcopy(complete)
        report["runs"][0]["invocations"][0]["executionSuccessful"] = False
        cases["unsuccessful invocation"] = report

        for path, filename in (
            ("README.md", "results.sarif"),
            ("docs/ci-cd.md", "results.sarif"),
            ("docs/ci-cd.md", "batesian-results.sarif"),
        ):
            filter_text = documented_filter(path, filename)
            for name, report in cases.items():
                with self.subTest(path=path, filename=filename, case=name):
                    self.assertEqual(accepts(filter_text, report), name == "complete")

    def test_json_coverage_filters(self):
        complete = {
            "schema_version": 1,
            "ruleset": {"selected": 2},
            "rule_outcomes": [
                {"status": "findings"},
                {"status": "no_findings"},
            ],
            "findings": [{"severity": "high"}],
        }
        cases = {"complete": complete, "v1.7.0": {"findings": []}}
        for name, changes in (
            ("skipped rule", {"rule_outcomes": [{"status": "findings"}, {"status": "skipped"}]}),
            ("errored rule", {"rule_outcomes": [{"status": "findings"}, {"status": "error"}]}),
            ("unknown status", {"rule_outcomes": [{"status": "findings"}, {"status": "unknown"}]}),
            ("missing outcome", {"rule_outcomes": [{"status": "findings"}]}),
            ("no selected rules", {"ruleset": {"selected": 0}, "rule_outcomes": []}),
        ):
            report = copy.deepcopy(complete)
            report.update(changes)
            cases[name] = report

        for filename in ("results.json", "batesian-results.json"):
            filter_text = documented_filter("docs/ci-cd.md", filename)
            for name, report in cases.items():
                with self.subTest(filename=filename, case=name):
                    self.assertEqual(accepts(filter_text, report), name == "complete")
            if filename == "batesian-results.json":
                critical = copy.deepcopy(complete)
                critical["findings"] = [{"severity": "critical"}]
                self.assertFalse(accepts(filter_text, critical))


if __name__ == "__main__":
    unittest.main()
