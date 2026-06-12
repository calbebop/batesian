package attack

// TokenOf exposes the bearer token field of HTTPClient for unit testing.
// It is defined in export_test.go so it is only compiled during tests.
func TokenOf(c *HTTPClient) string {
	return c.token
}
