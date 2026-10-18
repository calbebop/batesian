import unittest

from verify_release_candidate import verify_candidate


SHA = "a" * 40


def candidate(**overrides):
    run = {
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
    }
    run.update(overrides)
    return run


class VerifyReleaseCandidateTests(unittest.TestCase):
    def test_accepts_successful_manual_main_run(self):
        verify_candidate(SHA, SHA, {"workflow_runs": [candidate()]})

    def test_rejects_tag_not_on_current_main(self):
        with self.assertRaisesRegex(ValueError, "current main"):
            verify_candidate("b" * 40, SHA, {"workflow_runs": [candidate()]})

    def test_rejects_missing_manual_run(self):
        for runs in ({"workflow_runs": []}, {"workflow_runs": [candidate(event="push")]},
                     {"workflow_runs": [candidate(head_branch="dev")]},
                     {"workflow_runs": [candidate(head_sha="b" * 40)]},
                     {"workflow_runs": [candidate(status="in_progress", conclusion=None)]},
                     {"workflow_runs": [candidate(conclusion="failure")]}):
            with self.subTest(runs=runs), self.assertRaisesRegex(ValueError, "no successful manual CI"):
                verify_candidate(SHA, SHA, runs)

    def test_rejects_invalid_response(self):
        with self.assertRaisesRegex(ValueError, "invalid workflow runs"):
            verify_candidate(SHA, SHA, {"workflow_runs": None})
