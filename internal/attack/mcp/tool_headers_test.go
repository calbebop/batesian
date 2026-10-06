package mcp

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestToolParamHeaders(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"region": map[string]interface{}{"type": "string", "x-mcp-header": "Region"},
			"count":  map[string]interface{}{"type": "integer", "x-mcp-header": "Count"},
			"active": map[string]interface{}{"type": "boolean", "x-mcp-header": "Active"},
			"nested": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"greeting": map[string]interface{}{"type": "string", "x-mcp-header": "Greeting"},
				"absent":   map[string]interface{}{"type": "string", "x-mcp-header": "Absent"},
			}},
		},
	}
	args := map[string]interface{}{
		"region": "us-west1", "count": json.Number("9007199254740991"), "active": false,
		"nested": map[string]interface{}{"greeting": "Hello, 世界", "absent": nil},
	}
	got, err := toolParamHeaders(schema, args)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Mcp-Param-Region":   "us-west1",
		"Mcp-Param-Count":    "9007199254740991",
		"Mcp-Param-Active":   "false",
		"Mcp-Param-Greeting": "=?base64?SGVsbG8sIOS4lueVjA==?=",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("headers = %#v, want %#v", got, want)
	}
}

func TestToolParamHeaders_RejectsInvalidAnnotations(t *testing.T) {
	property := func(kind string, annotation interface{}) map[string]interface{} {
		return map[string]interface{}{"type": kind, "x-mcp-header": annotation}
	}
	cases := []struct {
		name   string
		schema map[string]interface{}
	}{
		{"root", property("string", "Root")},
		{"empty name", map[string]interface{}{"properties": map[string]interface{}{"a": property("string", "")}}},
		{"invalid token", map[string]interface{}{"properties": map[string]interface{}{"a": property("string", "X\r\nInjected")}}},
		{"number type", map[string]interface{}{"properties": map[string]interface{}{"a": property("number", "Amount")}}},
		{"duplicate case", map[string]interface{}{"properties": map[string]interface{}{
			"a": property("string", "Region"), "b": property("string", "region"),
		}}},
		{"array item", map[string]interface{}{"properties": map[string]interface{}{
			"items": map[string]interface{}{"type": "array", "items": property("string", "Item")},
		}}},
		{"composition", map[string]interface{}{"properties": map[string]interface{}{
			"a": map[string]interface{}{"oneOf": []interface{}{property("string", "Choice")}},
		}}},
		{"definition", map[string]interface{}{"$defs": map[string]interface{}{"a": property("string", "Def")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := toolParamHeaders(tc.schema, nil); err == nil {
				t.Fatal("invalid tool annotation was accepted")
			}
		})
	}
}

func TestToolParamHeaders_IgnoresExampleData(t *testing.T) {
	schema := map[string]interface{}{
		"properties": map[string]interface{}{
			"payload": map[string]interface{}{
				"type":     "object",
				"examples": []interface{}{map[string]interface{}{"x-mcp-header": "ordinary data"}},
			},
		},
	}
	if _, err := toolParamHeaders(schema, nil); err != nil {
		t.Fatalf("example data was treated as an annotation: %v", err)
	}
}

func TestToolParamHeaders_IntegerRangeAndTypes(t *testing.T) {
	schema := map[string]interface{}{"properties": map[string]interface{}{
		"count": map[string]interface{}{"type": "integer", "x-mcp-header": "Count"},
	}}
	for _, value := range []interface{}{json.Number("9007199254740992"), json.Number("9007199254740990.5"), 1.5, "2"} {
		if _, err := toolParamHeaders(schema, map[string]interface{}{"count": value}); err == nil {
			t.Errorf("accepted invalid integer value %v (%T)", value, value)
		}
	}
	for _, value := range []interface{}{json.Number("1.0"), int64(-1), float64(42)} {
		got, err := toolParamHeaders(schema, map[string]interface{}{"count": value})
		if err != nil || got["Mcp-Param-Count"] == "" {
			t.Errorf("rejected valid integer value %v (%T): headers=%v err=%v", value, value, got, err)
		}
	}
}

func TestToolRequest_MirrorsOnlyOnModernWire(t *testing.T) {
	schema := map[string]interface{}{"properties": map[string]interface{}{
		"region": map[string]interface{}{"type": "string", "x-mcp-header": "Region"},
	}}
	params := map[string]interface{}{"name": "lookup", "arguments": map[string]interface{}{"region": "us-west1"}}
	for _, era := range []Era{EraModern, EraLegacy} {
		s := mcpSession{Era: era}
		headers, body, err := s.toolRequest(1, params, schema)
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if era == EraModern {
			want = "us-west1"
		}
		if got := headers["Mcp-Param-Region"]; got != want {
			t.Errorf("era %v: Mcp-Param-Region = %q, want %q", era, got, want)
		}
		bodyParams := body["params"].(map[string]interface{})
		if !reflect.DeepEqual(bodyParams["arguments"], params["arguments"]) {
			t.Errorf("era %v: arguments changed", era)
		}
	}
}
