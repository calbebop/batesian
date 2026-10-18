import contextlib
import io
import json
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import validate_fastmcp
import validate_mcp_fixtures
import validate_oauth_dcr
import validate_push_callback_auth
import validate_secured_agent
from validation_outcomes import finding_quality_issues, incomplete_rules, rule_statuses


def report(*, findings=(), skipped=(), errors=(), outcomes=()):
    statuses = {rid: "no_findings" for rid in outcomes}
    statuses.update({rid: "findings" for rid in findings})
    statuses.update({rid: "skipped" for rid in skipped})
    statuses.update({rid: "error" for rid in errors})
    return {
        "findings": [{"rule_id": rid} for rid in findings],
        "skipped": [{"rule_id": rid} for rid in skipped],
        "errors": [{"rule_id": rid} for rid in errors],
        "rule_outcomes": [{"rule_id": rid, "status": status}
                          for rid, status in sorted(statuses.items())],
        "summary": {"total": len(findings)},
    }


class OutcomeTests(unittest.TestCase):
    def test_incomplete_rules_ignores_unrelated_skips(self):
        doc = report(skipped=["other", "expected"])
        self.assertEqual(incomplete_rules(doc, {"expected"}), (["expected"], []))

    def test_incomplete_rules_requires_outcome_fields(self):
        with self.assertRaises(ValueError):
            incomplete_rules({"findings": []}, {"expected"})

    def test_outcomes_require_every_expected_rule(self):
        with self.assertRaisesRegex(ValueError, "missing outcomes for expected"):
            rule_statuses(report(outcomes=["other"]), {"expected"})
        doc = report(outcomes=["expected"])
        doc["ruleset"] = {"selected": 2}
        with self.assertRaisesRegex(ValueError, "outcome count"):
            rule_statuses(doc, {"expected"})

    def test_outcomes_reject_malformed_and_duplicate_entries(self):
        malformed = [None, {}, {"rule_id": "expected", "status": "unknown"},
                     {"rule_id": 1, "status": "no_findings"},
                     {"rule_id": "expected", "status": []}]
        for item in malformed:
            with self.subTest(item=item), self.assertRaisesRegex(ValueError, "malformed"):
                rule_statuses({"rule_outcomes": [item]}, {"expected"})
        duplicate = report(outcomes=["expected"])
        duplicate["rule_outcomes"].append(duplicate["rule_outcomes"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            rule_statuses(duplicate, {"expected"})

    def test_positive_findings_require_confidence_and_evidence(self):
        rid = "a2a-task-cancel-idor-001"
        doc = report(findings=[rid])
        finding = doc["findings"][0]
        finding.update(confidence="confirmed", evidence="owner readback", target_url="http://fixture/")
        self.assertEqual(finding_quality_issues(doc, {rid: "confirmed"}), [])

        for field, value in (("confidence", "indicator"), ("evidence", "  "),
                             ("target_url", "")):
            with self.subTest(field=field):
                changed = dict(doc, findings=[dict(finding, **{field: value})])
                self.assertTrue(finding_quality_issues(changed, {rid: "confirmed"}))
        self.assertTrue(finding_quality_issues(doc, {"missing-rule": "confirmed"}))
        self.assertTrue(finding_quality_issues({"findings": None}, {rid: "confirmed"}))

    def test_clean_fixture_rejects_missing_outcome(self):
        with self.assertRaisesRegex(ValueError, "missing outcomes"):
            validate_mcp_fixtures.clean_rule(report(), "mcp-token-replay-001")

    def test_push_callback_scan_rejects_missing_outcome(self):
        for skipped in ([], [validate_push_callback_auth.RULE]):
            with self.subTest(skipped=skipped):
                doc = report(skipped=skipped)
                doc["rule_outcomes"] = []
                result = CompletedProcess([], 0, json.dumps(doc), "")
                with patch.object(validate_push_callback_auth.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(ValueError, "missing outcomes"):
                        validate_push_callback_auth.scan()

    def test_mcp_negative_control_rejects_malformed_outcome(self):
        doc = report(skipped=["mcp-log-optin-001"])
        doc["rule_outcomes"][0]["status"] = "unknown"
        result = CompletedProcess([], 0, json.dumps(doc), "")
        with patch.object(validate_mcp_fixtures.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "malformed"):
                validate_mcp_fixtures.scan(7804)

    def test_control_rule_ids_exist(self):
        known = {path.read_text(encoding="utf-8").splitlines()[0].removeprefix("id: ")
                 for path in Path("rules").rglob("*.yaml")}
        expected = (validate_secured_agent.SECURED_RULES |
                    validate_mcp_fixtures.UNAUTH_FAMILY |
                    validate_oauth_dcr.DCR_RULES |
                    {"mcp-tool-poisoning-001", validate_push_callback_auth.RULE})
        self.assertFalse(expected - known)

    def test_secured_agent_rejects_incomplete_rule(self):
        rid = "a2a-task-idor-001"
        positive = report(findings=validate_secured_agent.IDOR_RULES)
        paged = report(findings=["a2a-task-enumeration-001"])
        read = report(findings=[rid])
        for field in ("skipped", "errors"):
            with self.subTest(field=field):
                secured = report(outcomes=validate_secured_agent.SECURED_RULES,
                                 **{field: [rid]})
                scans = [(set(), secured), (set(validate_secured_agent.IDOR_RULES), positive),
                         ({"a2a-task-enumeration-001"}, paged), ({rid}, read)]
                with patch.object(validate_secured_agent, "scan_posture", side_effect=scans):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(validate_secured_agent.main(), 1)

    def test_mcp_patched_posture_rejects_incomplete_rule(self):
        rid = "mcp-token-replay-001"
        for field in ("skipped", "errors"):
            with self.subTest(field=field):
                scans = [({rid}, set(), report(findings=[rid])),
                         (set(), {rid} if field == "skipped" else set(), report(**{field: [rid]}))]
                with patch.object(validate_mcp_fixtures, "start", return_value=(None, None)), \
                     patch.object(validate_mcp_fixtures, "stop"), \
                     patch.object(validate_mcp_fixtures, "scan", side_effect=scans):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertFalse(validate_mcp_fixtures.token_replay())

    def test_fastmcp_rejects_incomplete_clean_rule(self):
        rid = "mcp-tool-poisoning-001"
        for field in ("skipped", "errors"):
            with self.subTest(field=field):
                scans = [(set(), report()),
                         ({"mcp-dns-rebind-origin-001"}, report(
                             findings=["mcp-dns-rebind-origin-001"], **{field: [rid]}))]
                with patch.object(validate_fastmcp, "start", return_value=(None, None)), \
                     patch.object(validate_fastmcp, "stop"), \
                     patch.object(validate_fastmcp, "scan", side_effect=scans):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(validate_fastmcp.main(), 1)

    def test_push_callback_signed_rejects_rule_error(self):
        rid = validate_push_callback_auth.RULE
        for field in ("skipped", "errors"):
            with self.subTest(field=field):
                signed = (set(), {rid}, set(), "skipped") if field == "skipped" \
                    else (set(), set(), {rid}, "error")
                scans = [({rid}, set(), set(), "findings"), signed,
                         (set(), {rid}, set(), "skipped")]
                with patch.object(validate_push_callback_auth, "start_fixture", return_value=(None, None)), \
                     patch.object(validate_push_callback_auth, "stop_fixture"), \
                     patch.object(validate_push_callback_auth, "scan", side_effect=scans):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(validate_push_callback_auth.main(), 1)

    def test_oauth_dcr_managed_rejects_incomplete_rules(self):
        rid = "mcp-oauth-dcr-001"
        findings = validate_oauth_dcr.DCR_RULES - {validate_oauth_dcr.CALLBACK_RULE}
        for field in ("skipped", "errors"):
            with self.subTest(field=field):
                managed_skips = [validate_oauth_dcr.CALLBACK_RULE]
                managed_errors = []
                if field == "skipped":
                    managed_skips.append(rid)
                else:
                    managed_errors.append(rid)
                managed = report(findings=findings, skipped=managed_skips, errors=managed_errors)
                managed["skipped"][0]["reason"] = "no metadata callback observed"
                unmanaged = report(findings=findings, skipped=[validate_oauth_dcr.CALLBACK_RULE])
                unmanaged["skipped"][0]["reason"] = "no metadata callback observed"
                scans = [(0, sorted(findings), managed), (3, sorted(findings), unmanaged)]
                with patch.object(validate_oauth_dcr, "start", return_value=(None, None, "http://fixture")), \
                     patch.object(validate_oauth_dcr, "stop"), \
                     patch.object(validate_oauth_dcr, "scan_count", side_effect=scans):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(validate_oauth_dcr.main(), 1)


if __name__ == "__main__":
    unittest.main()
