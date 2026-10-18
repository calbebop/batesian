import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def rule_ids(protocol):
    ids = []
    for path in (ROOT / "rules" / protocol).glob("*.yaml"):
        match = re.search(r"(?m)^id: (\S+)$", path.read_text(encoding="utf-8"))
        if match is None:
            raise AssertionError(f"missing rule id: {path}")
        ids.append(match.group(1))
    return ids


class RuleDocumentationTests(unittest.TestCase):
    def test_catalog_entries_and_counts(self):
        counts = {}
        for protocol in ("a2a", "mcp"):
            ids = rule_ids(protocol)
            content = (ROOT / "docs" / f"rules-{protocol}.md").read_text(encoding="utf-8")
            headings = re.findall(rf"(?m)^### ({protocol}-\S+)$", content)
            self.assertEqual(len(ids), len(set(ids)), f"duplicate {protocol} rule id")
            self.assertEqual(len(headings), len(set(headings)), f"duplicate {protocol} heading")
            self.assertEqual(set(headings), set(ids), f"{protocol} catalog mismatch")
            self.assertIn(f"ships **{len(ids)} rules**", content)
            counts[protocol] = len(ids)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"**{sum(counts.values())} bundled rules:**", readme)
        for protocol, count in counts.items():
            self.assertIn(f"[{count} {protocol.upper()} rules]", readme)
        self.assertIn(f"{counts['a2a']} A2A and {counts['mcp']} MCP", readme)


if __name__ == "__main__":
    unittest.main()
