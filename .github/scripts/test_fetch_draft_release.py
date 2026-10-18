import json
import subprocess
import unittest
from unittest.mock import patch

from fetch_draft_release import fetch_draft


def result(value):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(value), stderr="")


class FetchDraftReleaseTests(unittest.TestCase):
    @patch("fetch_draft_release.subprocess.run")
    def test_fetches_draft_by_id(self, run):
        run.side_effect = [
            result({"databaseId": 42, "isDraft": True, "tagName": "v1.8.0"}),
            result({"id": 42, "tag_name": "v1.8.0", "draft": True}),
        ]
        self.assertEqual(fetch_draft("calbebop/batesian", "v1.8.0")["id"], 42)
        self.assertEqual(run.call_args_list[1].args[0][-1], "repos/calbebop/batesian/releases/42")

    @patch("fetch_draft_release.subprocess.run")
    def test_rejects_published_release(self, run):
        run.return_value = result({"databaseId": 42, "isDraft": False, "tagName": "v1.8.0"})
        with self.assertRaisesRegex(ValueError, "expected a draft"):
            fetch_draft("calbebop/batesian", "v1.8.0")
        self.assertEqual(run.call_count, 1)

    @patch("fetch_draft_release.subprocess.run")
    def test_rejects_mismatched_id_response(self, run):
        run.side_effect = [
            result({"databaseId": 42, "isDraft": True, "tagName": "v1.8.0"}),
            result({"id": 43, "tag_name": "v1.8.0", "draft": True}),
        ]
        with self.assertRaisesRegex(ValueError, "different release"):
            fetch_draft("calbebop/batesian", "v1.8.0")


if __name__ == "__main__":
    unittest.main()
