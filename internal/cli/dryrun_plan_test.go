package cli

import (
	"bytes"
	"strings"
	"testing"

	attackpkg "github.com/calbebop/batesian/internal/attack"
)

// req is a compact constructor for a recorded request.
func req(rule, method, url, body string) attackpkg.RecordedRequest {
	return attackpkg.RecordedRequest{RuleID: rule, Method: method, URL: url, Body: body}
}

// The first attempt in an endpoint walk must NOT be marked, because it is the one a
// real scan sends. Marking the whole group flagged 97% of a real plan and implied
// all of it was skipped.
func TestEndpointCandidateProbes_MarksOnlyFallbacks(t *testing.T) {
	reqs := []attackpkg.RecordedRequest{
		req("r1", "POST", "http://t/mcp", `{"m":"initialize"}`),     // 0: sent
		req("r1", "POST", "http://t/mcp/mcp", `{"m":"initialize"}`), // 1: fallback
		req("r1", "POST", "http://t/mcp/api", `{"m":"initialize"}`), // 2: fallback
		req("r1", "POST", "http://t/mcp", `{"m":"tools/list"}`),     // 3: single URL, not a walk
		req("r2", "POST", "http://t/mcp", `{"m":"initialize"}`),     // 4: different rule, its own first
		req("r2", "POST", "http://t/mcp/api", `{"m":"initialize"}`), // 5: fallback
	}

	marked := endpointCandidateProbes(reqs)

	for _, i := range []int{1, 2, 5} {
		if !marked[i] {
			t.Errorf("request %d is a fallback attempt and should be marked", i)
		}
	}
	for _, i := range []int{0, 3, 4} {
		if marked[i] {
			t.Errorf("request %d must not be marked: index 0 and 4 are the first attempt of their walk and 3 is not a walk at all", i)
		}
	}
}

// A probe sent to exactly one URL is not a walk, however many times it repeats.
func TestEndpointCandidateProbes_SingleURLIsNotAWalk(t *testing.T) {
	reqs := []attackpkg.RecordedRequest{
		req("r1", "POST", "http://t/mcp", `{"m":"a"}`),
		req("r1", "POST", "http://t/mcp", `{"m":"a"}`),
	}
	if len(endpointCandidateProbes(reqs)) != 0 {
		t.Error("repeats at the same URL are not an endpoint walk and must not be marked")
	}
}

// The plan must not assert a request count as fact, and must state both directions
// in which it diverges from a real scan. It over-states endpoint fan-out, because no
// candidate can answer in a dry run, and under-states chained follow-ups.
func TestPrintDryRunPlan_StatesBothDivergences(t *testing.T) {
	rec := &attackpkg.Recorder{}
	rec.SetCurrentRule("r1")

	var buf bytes.Buffer
	printDryRunPlan(&buf, "http://t/mcp", rec)
	out := buf.String()

	if strings.Contains(out, "would be issued") {
		t.Error("the plan must not assert the recorded requests as the ones that would be issued; it is wrong in both directions")
	}
	for _, want := range []string{
		"Nothing was sent",
		"The host list above is exact",
		"cannot be expanded here",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan summary is missing %q; got: %s", want, out)
		}
	}
}

// The method is part of the grouping key, so a GET walk and a POST walk over the
// same URLs are separate walks and each keeps its own first attempt. The plan
// contains both: well-known card fetches are GETs, JSON-RPC probes are POSTs.
func TestEndpointCandidateProbes_MethodIsPartOfTheKey(t *testing.T) {
	reqs := []attackpkg.RecordedRequest{
		req("r1", "GET", "http://t/a/.well-known/agent-card.json", ""),  // 0: first GET
		req("r1", "GET", "http://t/b/.well-known/agent-card.json", ""),  // 1: fallback GET
		req("r1", "POST", "http://t/a/.well-known/agent-card.json", ""), // 2: first POST, own walk
		req("r1", "POST", "http://t/b/.well-known/agent-card.json", ""), // 3: fallback POST
	}

	marked := endpointCandidateProbes(reqs)

	if marked[0] || marked[2] {
		t.Error("each method's first attempt is sent and must not be marked")
	}
	if !marked[1] || !marked[3] {
		t.Error("each method's later attempts are fallbacks and must be marked")
	}
}
