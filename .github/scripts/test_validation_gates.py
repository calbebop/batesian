import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import patch

import validate_fastmcp
import validate_mcp_fixtures
import validate_oauth_dcr
import validate_push_callback_auth
import validate_secured_agent
from validation_outcomes import incomplete_rules


def report(*, findings=(), skipped=(), errors=()):
    return {
        "findings": [{"rule_id": rid} for rid in findings],
        "skipped": [{"rule_id": rid} for rid in skipped],
        "errors": [{"rule_id": rid} for rid in errors],
        "summary": {"total": len(findings)},
    }


class OutcomeTests(unittest.TestCase):
    def test_incomplete_rules_ignores_unrelated_skips(self):
        doc = report(skipped=["other", "expected"], errors=["expected"])
        self.assertEqual(incomplete_rules(doc, {"expected"}), (["expected"], ["expected"]))

    def test_incomplete_rules_requires_outcome_fields(self):
        with self.assertRaises(ValueError):
            incomplete_rules({"findings": []}, {"expected"})

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
                secured = report(**{field: [rid]})
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
                signed = (set(), {rid}, set()) if field == "skipped" else (set(), set(), {rid})
                scans = [({rid}, set(), set()), signed, (set(), {rid}, set())]
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
