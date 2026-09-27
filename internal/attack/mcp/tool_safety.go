package mcp

import "slices"

// declaresReadOnlyTool filters candidates; annotations do not authorize calls.
func declaresReadOnlyTool(readOnlyHint, destructiveHint *bool) bool {
	return readOnlyHint != nil && *readOnlyHint &&
		(destructiveHint == nil || !*destructiveHint)
}

func approvedToolName(name string, allowed []string) bool {
	return name != "" && slices.Contains(allowed, name)
}
