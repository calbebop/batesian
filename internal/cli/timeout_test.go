package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestTimeout(t *testing.T) {
	for _, seconds := range []int{-1, 0} {
		if _, err := requestTimeout(seconds); err == nil {
			t.Fatalf("requestTimeout(%d) succeeded", seconds)
		}
	}

	if got, err := requestTimeout(1); err != nil || got != time.Second {
		t.Fatalf("requestTimeout(1) = %s, %v", got, err)
	}

	if strconv.IntSize == 64 {
		max := (1<<63 - 1) / int64(time.Second)
		if got, err := requestTimeout(int(max)); err != nil || got != time.Duration(max)*time.Second {
			t.Fatalf("requestTimeout(%d) = %s, %v", max, got, err)
		}
		if _, err := requestTimeout(int(max + 1)); err == nil {
			t.Fatalf("requestTimeout(%d) succeeded", max+1)
		}
	}
}

func TestProbe_InvalidTimeoutStopsBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer target.Close()

	if probeCmd.Flags().Lookup("target") == nil {
		probeCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setProbeFlag(t, "target", target.URL)
	setProbeFlag(t, "protocol", "a2a")
	setProbeFlag(t, "output", "table")
	setProbeFlag(t, "timeout", "0")
	setProbeFlag(t, "proxy", "")

	err := runProbe(probeCmd, nil)
	const want = "--timeout must be greater than zero"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if hits.Load() != 0 {
		t.Fatalf("target received %d requests", hits.Load())
	}
}

func TestScan_InvalidTimeoutStopsBeforeNetwork(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	var oauthHits, targetHits atomic.Int32
	oauth := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		oauthHits.Add(1)
	}))
	defer oauth.Close()
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	t.Setenv("BATESIAN_TOKEN", "")
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "target", target.URL)
	setScanFlag(t, "output", "table")
	setScanFlag(t, "timeout", "-1")
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "token-url", oauth.URL)
	setScanFlag(t, "auth-url", "")
	setScanFlag(t, "dry-run", "false")

	err := runScan(scanCmd, nil)
	const want = "--timeout must be greater than zero"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if oauthHits.Load() != 0 || targetHits.Load() != 0 {
		t.Fatalf("network calls before timeout validation: oauth=%d target=%d", oauthHits.Load(), targetHits.Load())
	}
}
