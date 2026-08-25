package mcp

// Test seams over the shadow-surface port list. The harness needs to aim the
// executor at ephemeral listeners instead of the documented product ports;
// production callers never touch these.

// ShadowPorts returns a copy of the candidate port list.
func ShadowPorts() []int {
	return append([]int(nil), shadowPorts...)
}

// SetShadowPorts replaces the candidate port list.
func SetShadowPorts(ports []int) {
	shadowPorts = append([]int(nil), ports...)
}
