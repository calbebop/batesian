import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from verify_release import (
    check_dist,
    check_draft,
    check_rule_claim,
    digest,
    expected_files,
)


class VerifyReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        for protocol, count in (("a2a", 2), ("mcp", 3)):
            directory = self.root / "rules" / protocol
            directory.mkdir(parents=True)
            for index in range(count):
                (directory / f"rule-{index}.yaml").touch()
        self.version = "1.8.0"
        self.tag = f"v{self.version}"
        self.files, self.archives = expected_files(self.version, signed=True)
        for name in self.archives:
            path = self.dist / name
            entries = ("README.md", "LICENSE", "CONTRIBUTING.md")
            binary = "batesian.exe" if name.endswith(".zip") else "batesian"
            if name.endswith(".zip"):
                with zipfile.ZipFile(path, "w") as archive:
                    for entry in (*entries, binary):
                        archive.writestr(entry, b"test")
            else:
                with tarfile.open(path, "w:gz") as archive:
                    for entry in (*entries, binary):
                        data = b"test"
                        info = tarfile.TarInfo(entry)
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
            (self.dist / f"{name}.sbom.json").write_text(
                json.dumps({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [{"name": "batesian", "type": "application"}],
                }),
                encoding="utf-8",
            )
        self.write_checksums()
        (self.dist / "checksums.txt.sigstore.json").write_text("{}", encoding="utf-8")

    def write_checksums(self):
        names = sorted(self.files - {"checksums.txt", "checksums.txt.sigstore.json"})
        (self.dist / "checksums.txt").write_text(
            "".join(f"{digest(self.dist / name)}  {name}\n" for name in names),
            encoding="utf-8",
        )

    def release(self):
        return {
            "tag_name": self.tag,
            "name": self.tag,
            "draft": True,
            "body": f"## Batesian {self.tag}\n5 bundled attack rules (2 A2A + 3 MCP)",
            "assets": [
                {
                    "name": name,
                    "state": "uploaded",
                    "size": (self.dist / name).stat().st_size,
                    "digest": f"sha256:{digest(self.dist / name)}",
                }
                for name in sorted(self.files)
            ],
        }

    def test_complete_draft(self):
        expected = check_dist(self.dist, self.version, signed=True)
        check_draft(self.release(), self.dist, self.tag, expected, self.root)

    def test_rejects_spdx_sbom(self):
        name = next(iter(self.archives))
        (self.dist / f"{name}.sbom.json").write_text(
            json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8"
        )
        self.write_checksums()
        with self.assertRaisesRegex(ValueError, "not a CycloneDX"):
            check_dist(self.dist, self.version, signed=True)

    def test_rejects_tampered_archive(self):
        name = next(iter(self.archives))
        with (self.dist / name).open("ab") as output:
            output.write(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            check_dist(self.dist, self.version, signed=True)

    def test_rejects_missing_draft_asset(self):
        release = self.release()
        release["assets"].pop()
        with self.assertRaisesRegex(ValueError, "asset set"):
            check_draft(release, self.dist, self.tag, self.files, self.root)

    def test_rejects_wrong_draft_digest(self):
        release = self.release()
        release["assets"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "draft asset differs"):
            check_draft(release, self.dist, self.tag, self.files, self.root)

    def test_rejects_stale_rule_count(self):
        with self.assertRaisesRegex(ValueError, "rule count"):
            check_rule_claim("47 bundled attack rules (19 A2A + 28 MCP)", self.root)


if __name__ == "__main__":
    unittest.main()
