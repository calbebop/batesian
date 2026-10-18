"""Read a draft release by ID because GitHub's tag lookup omits drafts."""

import json
import subprocess
import sys


def fetch_draft(repo: str, tag: str) -> dict:
    view = subprocess.run(
        ["gh", "release", "view", tag, "--repo", repo, "--json", "databaseId,isDraft,tagName"],
        check=True,
        capture_output=True,
        text=True,
    )
    summary = json.loads(view.stdout)
    release_id = summary.get("databaseId")
    if (
        summary.get("tagName") != tag
        or summary.get("isDraft") is not True
        or type(release_id) is not int
        or release_id <= 0
    ):
        raise ValueError("expected a draft release for the tag")

    response = subprocess.run(
        ["gh", "api", f"repos/{repo}/releases/{release_id}"],
        check=True,
        capture_output=True,
        text=True,
    )
    release = json.loads(response.stdout)
    if release.get("id") != release_id or release.get("tag_name") != tag or not release.get("draft"):
        raise ValueError("draft release lookup returned a different release")
    return release


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: fetch_draft_release.py OWNER/REPO TAG")
    try:
        print(json.dumps(fetch_draft(sys.argv[1], sys.argv[2])))
    except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError) as error:
        sys.exit(f"[FAIL] draft release lookup: {error}")
