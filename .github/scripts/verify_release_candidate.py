"""Require a successful manual CI run for the tagged main commit."""

import argparse
import json
import sys


def verify_candidate(main_sha, tag_sha, runs):
    if not main_sha or main_sha != tag_sha:
        raise ValueError("release tag does not point to the current main commit")
    if not isinstance(runs, dict) or not isinstance(runs.get("workflow_runs"), list):
        raise ValueError("invalid workflow runs response")
    for run in runs["workflow_runs"]:
        if not isinstance(run, dict):
            continue
        if (
            run.get("event") == "workflow_dispatch"
            and run.get("head_branch") == "main"
            and run.get("head_sha") == tag_sha
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
        ):
            return
    raise ValueError("no successful manual CI run found for the tagged main commit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--main-sha", required=True)
    parser.add_argument("--tag-sha", required=True)
    args = parser.parse_args()
    verify_candidate(args.main_sha, args.tag_sha, json.load(sys.stdin))
    print("[PASS] release tag matches the reviewed main candidate")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, json.JSONDecodeError) as error:
        sys.exit(f"[FAIL] release candidate: {error}")
