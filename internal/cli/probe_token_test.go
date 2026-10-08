package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/protocol/a2a"
)

func TestProbeTokenSources(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "batesian.yaml"), []byte("token: file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	if probeCmd.Flags().Lookup("target") == nil {
		probeCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	previousContext := probeCmd.Context()
	probeCmd.SetContext(context.Background())
	t.Cleanup(func() { probeCmd.SetContext(previousContext) })

	for _, tc := range []struct {
		name string
		env  string
		flag string
		want string
	}{
		{name: "environment", env: "env-secret", want: "Bearer env-secret"},
		{name: "flag overrides environment", env: "env-secret", flag: "flag-secret", want: "Bearer flag-secret"},
		{name: "config is scan only", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BATESIAN_TOKEN", tc.env)
			var mu sync.Mutex
			var authHeaders []string
			description := strings.TrimPrefix(tc.want, "Bearer ")
			if description == "" {
				description = "public"
			}
			card := strings.Replace(validProbeA2ACard, "Test agent", description, 1)
			card = strings.Replace(card, `"extendedAgentCard":true`, `"extendedAgentCard":false`, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != a2a.WellKnownPath {
					http.NotFound(w, r)
					return
				}
				mu.Lock()
				authHeaders = append(authHeaders, r.Header.Get("Authorization"))
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, card)
			}))
			defer srv.Close()

			setProbeFlag(t, "target", srv.URL)
			setProbeFlag(t, "protocol", "a2a")
			setProbeFlag(t, "output", "table")
			setProbeFlag(t, "token", tc.flag)
			setProbeFlag(t, "proxy", "")
			output, err := captureCLIOutput(t, func() error { return runProbe(probeCmd, nil) })
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			mu.Lock()
			headers := append([]string(nil), authHeaders...)
			mu.Unlock()
			if len(headers) == 0 {
				t.Fatal("probe did not fetch the Agent Card")
			}
			for _, got := range headers {
				if got != tc.want {
					t.Fatalf("Authorization = %q, want %q", got, tc.want)
				}
			}
			if description != "public" && strings.Contains(output, description) {
				t.Fatal("probe output disclosed the selected bearer token")
			}
		})
	}
}

func TestProbeMCPUsesEnvironmentToken(t *testing.T) {
	const token = "mcp-env-secret"
	t.Setenv("BATESIAN_TOKEN", token)
	var mu sync.Mutex
	var authHeaders []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	if probeCmd.Flags().Lookup("target") == nil {
		probeCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	previousContext := probeCmd.Context()
	probeCmd.SetContext(context.Background())
	t.Cleanup(func() { probeCmd.SetContext(previousContext) })
	setProbeFlag(t, "target", srv.URL+"/mcp")
	setProbeFlag(t, "protocol", "mcp")
	setProbeFlag(t, "output", "table")
	setProbeFlag(t, "token", "")
	setProbeFlag(t, "proxy", "")

	output, err := captureCLIOutput(t, func() error { return runProbe(probeCmd, nil) })
	if err == nil {
		t.Fatal("expected the rejecting server to stop the probe")
	}
	if strings.Contains(output, token) || strings.Contains(err.Error(), token) {
		t.Fatal("probe output disclosed the environment token")
	}
	mu.Lock()
	headers := append([]string(nil), authHeaders...)
	mu.Unlock()
	if len(headers) == 0 {
		t.Fatal("probe made no MCP requests")
	}
	for _, header := range headers {
		if header == "Bearer "+token {
			return
		}
	}
	t.Fatalf("no MCP request used the environment token: %q", headers)
}
