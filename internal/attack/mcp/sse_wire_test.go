package mcp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// sseWrap re-frames a JSON handler's response as a single SSE event, which is how
// real streamable-HTTP MCP servers answer a POST. It lets one fixture be driven
// over both transports so the two can be compared.
//
// This matters because the shared client's SSE branch had no unit coverage at all
// while being the branch every real MCP server takes: no httptest fixture in either
// rule package answered a JSON-RPC POST with Content-Type: text/event-stream. The
// rules were only ever tested against the JSON branch.
func sseWrap(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r)

		for k, vs := range rec.Header() {
			if strings.EqualFold(k, "Content-Type") || strings.EqualFold(k, "Content-Length") {
				continue
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		body := strings.TrimSpace(rec.Body.String())
		if rec.Code != http.StatusOK || body == "" {
			// Non-2xx and empty replies are not streamed by a real server either.
			w.WriteHeader(rec.Code)
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// A notification first, which the binding permits and which used to be
		// mistaken for the reply.
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\","+
			"\"params\":{\"level\":\"debug\",\"data\":\"streaming\"}}\n\n")
		for _, line := range strings.Split(body, "\n") {
			fmt.Fprintf(w, "data: %s\n", line)
		}
		fmt.Fprint(w, "\n")
	})
}

// The same server, over both transports, must produce the same findings. A rule
// that only works against a JSON body is a rule that does not work against a real
// MCP server.
func TestUnauthFamily_SSETransportMatchesJSON(t *testing.T) {
	jsonSrv := listingServer(t, "open")
	defer jsonSrv.Close()

	inner := listingServer(t, "open")
	defer inner.Close()
	sseSrv := httptest.NewServer(sseWrap(inner.Config.Handler))
	defer sseSrv.Close()

	titles := func(target string) []string {
		var out []string
		for id, mk := range unauthFamily() {
			exec := mk(attack.RuleContext{ID: id, Name: id, Severity: "high"})
			findings, err := exec.Execute(context.Background(), target, testOpts())
			if err != nil {
				out = append(out, id+": ERR "+err.Error())
				continue
			}
			for range findings {
				out = append(out, id)
			}
		}
		sort.Strings(out)
		return out
	}

	overJSON := titles(jsonSrv.URL)
	overSSE := titles(sseSrv.URL)

	if len(overJSON) == 0 {
		t.Fatal("the JSON control produced no findings; the comparison would be vacuous")
	}
	if strings.Join(overJSON, "|") != strings.Join(overSSE, "|") {
		t.Errorf("transport changed the result.\n over JSON: %v\n over SSE : %v", overJSON, overSSE)
	}
}
