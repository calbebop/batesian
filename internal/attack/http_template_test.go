package attack

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalBodyExpandsOnlyJSONValues(t *testing.T) {
	vars := Vars{BaseURL: "https://example.com/a\"b\\c", OOBListener: "line\nnext", RandID: "probe-1"}
	body := map[string]any{
		"{{BaseURL}}": []any{map[string]any{
			"url": "{{BaseURL}}", "callback": "{{OOBListener}}", "id": "{{RandID}}",
		}, true},
		"large_number": json.Number("9007199254740993"),
	}
	encoded, err := marshalBody(body, vars)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var got map[string]any
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("invalid expanded JSON %q: %v", encoded, err)
	}
	items := got["{{BaseURL}}"].([]any)
	fields := items[0].(map[string]any)
	if fields["url"] != vars.BaseURL || fields["callback"] != vars.OOBListener || fields["id"] != vars.RandID {
		t.Fatalf("expanded values = %+v", fields)
	}
	if got["large_number"] != json.Number("9007199254740993") || items[1] != true {
		t.Fatalf("non-string values changed: %+v", got)
	}
	if body["{{BaseURL}}"].([]any)[0].(map[string]any)["url"] != "{{BaseURL}}" {
		t.Fatal("request template was mutated")
	}
}

func TestMarshalBodyRejectsInvalidRawJSON(t *testing.T) {
	if _, err := marshalBody(json.RawMessage(`{"broken":`), Vars{}); err == nil {
		t.Fatal("invalid JSON body was accepted")
	}
}
