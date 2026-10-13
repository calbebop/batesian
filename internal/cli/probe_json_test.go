package cli

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/protocol/a2a"
	"github.com/calbebop/batesian/internal/report"
)

func TestBuildJSONOutputCardProvenance(t *testing.T) {
	const raw = " {\n  \"name\": \"Agent\", \"extension\": {\"sequence\": 9007199254740993}\n}\n"
	response := &a2a.ProbeResult{
		URL:  "https://agent.example/.well-known/agent-card.json",
		Body: []byte(raw),
	}
	result := &report.ProbeResult{URL: "https://agent.example"}

	doc, err := buildJSONOutput(response, result, newOutputRedactor(result.URL))
	if err != nil {
		t.Fatalf("build JSON output: %v", err)
	}
	card := doc["agent_card"].(map[string]any)
	extension := card["extension"].(map[string]any)
	if got := extension["sequence"]; got != json.Number("9007199254740993") {
		t.Errorf("extension sequence = %v, want exact integer", got)
	}
	provenance := doc["agent_card_provenance"].(map[string]any)
	if got := provenance["source_url"]; got != response.URL {
		t.Errorf("source URL = %q, want %q", got, response.URL)
	}
	if got := provenance["representation"]; got != "parsed_redacted" {
		t.Errorf("representation = %q, want parsed_redacted", got)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(response.Body))
	if got := provenance["retrieved_sha256"]; got != wantDigest {
		t.Errorf("retrieved digest = %q, want %q", got, wantDigest)
	}
}

func TestBuildJSONOutputRedactsCardAndSourceURL(t *testing.T) {
	const raw = `{"name":"Agent","extension":{"endpoint":"https://alice:password@agent.example/rpc?token=private","note":"credential-value"}}`
	response := &a2a.ProbeResult{
		URL:  "https://alice:password@agent.example/.well-known/agent-card.json?token=private",
		Body: []byte(raw),
	}
	redactor := newOutputRedactor("https://alice:password@agent.example")
	redactor.addSecret("credential-value")

	doc, err := buildJSONOutput(response, &report.ProbeResult{}, redactor)
	if err != nil {
		t.Fatalf("build JSON output: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal JSON output: %v", err)
	}
	for _, secret := range []string{"alice", "password", "private", "credential-value"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("output contains %q: %s", secret, encoded)
		}
	}
	provenance := doc["agent_card_provenance"].(map[string]any)
	if got := provenance["retrieved_sha256"]; got != fmt.Sprintf("%x", sha256.Sum256(response.Body)) {
		t.Errorf("retrieved digest = %q, want digest of unredacted response", got)
	}
}

func TestBuildJSONOutputRejectsInvalidCard(t *testing.T) {
	for _, body := range []string{"", "null", `{"name":`} {
		t.Run(body, func(t *testing.T) {
			_, err := buildJSONOutput(&a2a.ProbeResult{Body: []byte(body)}, &report.ProbeResult{}, newOutputRedactor(""))
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
