#!/usr/bin/env python3
"""Check release archives, SBOMs, checksums, notes, and draft assets."""

import argparse
import hashlib
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path


TARGETS = (
    ("darwin", "arm64", "tar.gz"),
    ("darwin", "x86_64", "tar.gz"),
    ("linux", "arm64", "tar.gz"),
    ("linux", "x86_64", "tar.gz"),
    ("windows", "x86_64", "zip"),
)
RULE_CLAIM = re.compile(r"(\d+) bundled attack rules \((\d+) A2A \+ (\d+) MCP\)")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def expected_files(version, signed):
    archives = {
        f"batesian_{version}_{os_name}_{arch}.{extension}"
        for os_name, arch, extension in TARGETS
    }
    files = archives | {f"{name}.sbom.json" for name in archives} | {"checksums.txt"}
    if signed:
        files.add("checksums.txt.sigstore.json")
    return files, archives


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def rule_counts(root):
    a2a = len(list((root / "rules" / "a2a").glob("*.yaml")))
    mcp = len(list((root / "rules" / "mcp").glob("*.yaml")))
    if not a2a or not mcp:
        raise ValueError("rule catalogs are empty")
    return a2a + mcp, a2a, mcp


def check_rule_claim(text, root):
    claim = RULE_CLAIM.search(text)
    if not claim:
        raise ValueError("release notes omit the bundled rule count")
    if tuple(map(int, claim.groups())) != rule_counts(root):
        raise ValueError("release notes rule count differs from the bundled catalogs")


def snapshot_version(dist):
    suffix = "_linux_x86_64.tar.gz"
    names = [p.name for p in dist.glob(f"batesian_*{suffix}")]
    if len(names) != 1:
        raise ValueError("expected one Linux x86_64 snapshot archive")
    return names[0][len("batesian_") : -len(suffix)]


def check_archive(path, windows):
    if windows:
        with zipfile.ZipFile(path) as archive:
            names = {Path(name).name for name in archive.namelist()}
    else:
        with tarfile.open(path, "r:gz") as archive:
            names = {Path(name).name for name in archive.getnames()}
    required = {"README.md", "LICENSE", "CONTRIBUTING.md"}
    required.add("batesian.exe" if windows else "batesian")
    if not required <= names:
        raise ValueError(f"{path.name} is missing archive entries: {required - names}")


def check_dist(dist, version, signed):
    expected, archives = expected_files(version, signed)
    missing = expected - {p.name for p in dist.iterdir() if p.is_file()}
    if missing:
        raise ValueError(f"missing release files: {sorted(missing)}")

    for name in archives:
        check_archive(dist / name, name.endswith(".zip"))
        sbom = json.loads((dist / f"{name}.sbom.json").read_text(encoding="utf-8"))
        if (
            sbom.get("bomFormat") != "CycloneDX"
            or not sbom.get("specVersion")
            or not sbom.get("components")
        ):
            raise ValueError(f"{name}.sbom.json is not a CycloneDX SBOM")

    checksums = {}
    for line in (dist / "checksums.txt").read_text(encoding="utf-8").splitlines():
        checksum, separator, name = line.partition("  ")
        if not separator or not SHA256.fullmatch(checksum) or name in checksums:
            raise ValueError(f"invalid checksum line: {line!r}")
        checksums[name] = checksum
    if set(checksums) != expected - {"checksums.txt", "checksums.txt.sigstore.json"}:
        raise ValueError("checksums do not cover exactly the archives and SBOMs")
    for name, checksum in checksums.items():
        if digest(dist / name) != checksum:
            raise ValueError(f"checksum mismatch: {name}")
    if signed:
        json.loads((dist / "checksums.txt.sigstore.json").read_text(encoding="utf-8"))
    return expected


def check_draft(release, dist, tag, expected, root):
    if release.get("tag_name") != tag or not release.get("draft"):
        raise ValueError("release is not a draft for the expected tag")
    if release.get("name") != tag or f"## Batesian {tag}" not in release.get("body", ""):
        raise ValueError("release title or version is incorrect")
    check_rule_claim(release["body"], root)

    assets = release.get("assets", [])
    names = [asset.get("name") for asset in assets]
    if len(names) != len(set(names)) or set(names) != expected:
        raise ValueError(f"draft asset set differs from expected files: {names}")
    for asset in assets:
        path = dist / asset["name"]
        if (
            asset.get("state") != "uploaded"
            or asset.get("size") != path.stat().st_size
            or asset.get("digest") != f"sha256:{digest(path)}"
        ):
            raise ValueError(f"draft asset differs from local file: {asset['name']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--tag")
    parser.add_argument("--release-json", help="GitHub release API JSON, or - for stdin")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    check_rule_claim((root / ".goreleaser.yaml").read_text(encoding="utf-8"), root)
    version = args.tag.removeprefix("v") if args.tag else snapshot_version(args.dist)
    expected = check_dist(args.dist, version, signed=bool(args.tag))
    if args.tag:
        if not args.release_json:
            parser.error("--release-json is required with --tag")
        source = sys.stdin if args.release_json == "-" else open(args.release_json, encoding="utf-8")
        try:
            check_draft(json.load(source), args.dist, args.tag, expected, root)
        finally:
            if source is not sys.stdin:
                source.close()
    summary = f"[PASS] {version}: archives, CycloneDX SBOMs, checksums, rule count"
    print(summary + (", draft assets" if args.tag else ""))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as error:
        sys.exit(f"[FAIL] release verification: {error}")
