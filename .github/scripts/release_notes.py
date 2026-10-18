"""Extract the current release section from CHANGELOG.md for GoReleaser."""

import re
import sys
from pathlib import Path


def extract_notes(changelog: str, tag: str) -> str:
    match = re.fullmatch(r"(v\d+\.\d+\.\d+)(?:-[0-9A-Za-z.-]+)?", tag)
    if not match:
        raise ValueError(f"invalid release tag: {tag}")

    heading = f"## {match.group(1)}"
    lines = changelog.splitlines()
    try:
        start = lines.index(heading) + 1
    except ValueError as exc:
        raise ValueError(f"missing {heading} in CHANGELOG.md") from exc

    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines))
    notes = "\n".join(lines[start:end]).strip()
    if not notes:
        raise ValueError(f"empty {heading} in CHANGELOG.md")
    return notes + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: release_notes.py TAG")
    source = Path(__file__).resolve().parents[2] / "CHANGELOG.md"
    try:
        sys.stdout.write(extract_notes(source.read_text(encoding="utf-8"), sys.argv[1]))
    except ValueError as exc:
        sys.exit(str(exc))
