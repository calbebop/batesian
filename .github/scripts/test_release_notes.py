"""Tests for release note extraction."""

import unittest

from release_notes import extract_notes


class ReleaseNotesTests(unittest.TestCase):
    def test_extracts_only_requested_release(self):
        source = "# Changelog\n\n## v1.8.0\n\n### Fixes\n\n- Safer findings.\n\n## v1.7.0\n\n- Earlier.\n"
        self.assertEqual(extract_notes(source, "v1.8.0"), "### Fixes\n\n- Safer findings.\n")
        self.assertEqual(extract_notes(source, "v1.8.0-rc.1"), "### Fixes\n\n- Safer findings.\n")

    def test_rejects_missing_or_empty_section(self):
        for source in ("## v1.7.0\n- Earlier.\n", "## v1.8.0\n\n## v1.7.0\n- Earlier.\n"):
            with self.assertRaises(ValueError):
                extract_notes(source, "v1.8.0")

    def test_rejects_invalid_tag(self):
        with self.assertRaises(ValueError):
            extract_notes("## v1.8.0\n- Fix.\n", "main")


if __name__ == "__main__":
    unittest.main()
