# Release checklist

## Check the candidate

1. Merge the release fixes and confirm the push CI run passes on the intended
   `main` commit.
2. Run `gh workflow run ci.yml --ref main`. Confirm the run uses that commit.
3. Require Build & Test, Lint, Vulnerability Scan, Validate release targets,
   and Verify release snapshot to pass. Release (goreleaser) must be skipped.
4. Check the changelog, README version references, bundled rule count, and
   release notes. Record the go/no-go decision in the release checklist issue.

The manual CI run validates the merged candidate without creating a tag or
release. A passing PR snapshot does not replace this check on `main`.

## Publish

Only after the go/no-go decision, tag the verified commit and push the version
tag. The release job requires the tag to point to the current `main` commit and
a successful manual CI run on that exact commit. A tag push reruns the gates,
builds a draft release, verifies its assets, signature, and provenance, then
publishes it. If a gate fails, leave the release unpublished and fix the
candidate through a PR before retrying.

This gate only applies to tags whose commits contain the current workflow.
Restrict release tag creation separately; a tag on an older commit can run the
older workflow without this check.
