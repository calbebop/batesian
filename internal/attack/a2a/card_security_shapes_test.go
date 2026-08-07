package a2a

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The AgentCard's requirements list has two wire shapes, and every finding this
// rule produces names the scheme it read out of one of them. These cover the
// parser directly, because the interesting cases are all in how a card is shaped
// rather than in the HTTP exchange around it.
func TestDeclaredAuthRequirement_Shapes(t *testing.T) {
	tests := []struct {
		name         string
		card         string
		wantSchemes  []string
		wantRequired bool
		why          string
	}{
		{
			name:         "v1.0 proto shape",
			card:         `{"securityRequirements":[{"schemes":{"bearerAuth":{"list":["a2a:invoke"]}}}]}`,
			wantSchemes:  []string{"bearerAuth"},
			wantRequired: true,
			why:          "both official SDKs nest the names under schemes; this is what every real v1.0 card serves",
		},
		{
			name:         "v1.0 proto shape, several schemes",
			card:         `{"securityRequirements":[{"schemes":{"bearerAuth":{"list":[]},"apiKey":{"list":[]}}}]}`,
			wantSchemes:  []string{"apiKey", "bearerAuth"},
			wantRequired: true,
			why:          "every name in the map is required, and the result is sorted",
		},
		{
			name:         "v1.0 field with the OpenAPI-flat shape",
			card:         `{"securityRequirements":[{"bearerAuth":["a2a:invoke"]}]}`,
			wantSchemes:  []string{"bearerAuth"},
			wantRequired: true,
			why:          "a hand-rolled card may use the flat shape under the v1.0 field name",
		},
		{
			name:         "v0.3 security field",
			card:         `{"security":[{"bearerAuth":[]}]}`,
			wantSchemes:  []string{"bearerAuth"},
			wantRequired: true,
			why:          "the v0.3 spelling must still be read",
		},
		{
			name:         "v1.0 entry with an empty schemes map",
			card:         `{"securityRequirements":[{"schemes":{}}]}`,
			wantRequired: false,
			why:          "a proto message always carries its map field, so this is how v1.0 says anonymous is permitted",
		},
		{
			name:         "empty entry in the list",
			card:         `{"securityRequirements":[{},{"schemes":{"bearerAuth":{"list":[]}}}]}`,
			wantRequired: false,
			why:          "an empty requirement object permits anonymous access whatever else the list holds",
		},
		{
			name:         "no security declaration",
			card:         `{"name":"agent"}`,
			wantRequired: false,
			why:          "nothing was promised, so nothing can be unenforced",
		},
		{
			name:         "empty requirements list",
			card:         `{"securityRequirements":[]}`,
			wantRequired: false,
			why:          "an empty list declares no requirement",
		},
		{
			name:         "malformed entry",
			card:         `{"securityRequirements":["bearerAuth"]}`,
			wantRequired: false,
			why:          "a non-object entry is not a requirement to assert a violation against",
		},
		{
			// A v0.3 card may legitimately name a scheme "schemes". Its value is a
			// scope array rather than an object, which is what tells the two
			// shapes apart, so the nested branch must not claim this one.
			name:         "v0.3 scheme literally named schemes",
			card:         `{"security":[{"schemes":["read"]}]}`,
			wantSchemes:  []string{"schemes"},
			wantRequired: true,
			why:          "the shapes are distinguished by structure, not by the name of the key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var card map[string]interface{}
			if err := json.Unmarshal([]byte(tt.card), &card); err != nil {
				t.Fatalf("bad test card: %v", err)
			}
			schemes, required := declaredAuthRequirement(card)
			if required != tt.wantRequired {
				t.Errorf("required = %v, want %v (%s)", required, tt.wantRequired, tt.why)
			}
			if tt.wantRequired && !reflect.DeepEqual(schemes, tt.wantSchemes) {
				t.Errorf("schemes = %v, want %v (%s)", schemes, tt.wantSchemes, tt.why)
			}
		})
	}
}
