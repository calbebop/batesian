package mcp

// declaresReadOnlyTool reports whether annotations explicitly and consistently
// describe a tool as read-only. destructiveHint=false is not sufficient: MCP
// defines that as an additive update when readOnlyHint is false.
func declaresReadOnlyTool(readOnlyHint, destructiveHint *bool) bool {
	return readOnlyHint != nil && *readOnlyHint &&
		(destructiveHint == nil || !*destructiveHint)
}
