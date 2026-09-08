package cli

import "testing"

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{name: "HTTPS origin", target: "https://agent.example.com"},
		{name: "localhost", target: "http://localhost:3001"},
		{name: "IPv4", target: "http://127.0.0.1:3001/mcp"},
		{name: "IPv6", target: "http://[::1]:3001/mcp"},
		{name: "nested path", target: "https://agent.example.com/services/a2a"},
		{name: "escaped path", target: "https://agent.example.com/services/a%20b"},
		{name: "query", target: "https://agent.example.com/mcp?tenant=one"},
		{name: "empty", wantErr: true},
		{name: "whitespace", target: " ", wantErr: true},
		{name: "bare host", target: "localhost:3001", wantErr: true},
		{name: "relative path", target: "/mcp", wantErr: true},
		{name: "network path", target: "//agent.example.com/mcp", wantErr: true},
		{name: "unsupported scheme", target: "ftp://agent.example.com", wantErr: true},
		{name: "missing host", target: "https:///mcp", wantErr: true},
		{name: "opaque HTTP URL", target: "http:localhost", wantErr: true},
		{name: "port without host", target: "http://:8080", wantErr: true},
		{name: "invalid IPv6", target: "http://[::1", wantErr: true},
		{name: "invalid escape", target: "https://agent.example.com/%zz", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTargetURL(tc.target)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateTargetURL(%q) error = %v, wantErr %v", tc.target, err, tc.wantErr)
			}
		})
	}
}

func TestProbeRejectsInvalidTarget(t *testing.T) {
	if probeCmd.Flags().Lookup("target") == nil {
		probeCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	for _, protocol := range []string{"a2a", "mcp"} {
		t.Run(protocol, func(t *testing.T) {
			setProbeFlag(t, "target", "https:///mcp")
			setProbeFlag(t, "protocol", protocol)
			setProbeFlag(t, "output", "table")
			setProbeFlag(t, "proxy", "")

			err := runProbe(probeCmd, nil)
			const want = `invalid target URL "https:///mcp": missing host`
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
		})
	}
}

func setProbeFlag(t *testing.T, name, value string) {
	t.Helper()
	flag := probeCmd.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("unknown probe flag %q", name)
	}
	oldValue, oldChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		_ = flag.Value.Set(oldValue)
		flag.Changed = oldChanged
	})
	if err := flag.Value.Set(value); err != nil {
		t.Fatalf("setting %s: %v", name, err)
	}
	flag.Changed = true
}
