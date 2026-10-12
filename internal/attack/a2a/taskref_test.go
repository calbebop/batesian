package a2a

import (
	"reflect"
	"testing"
)

func TestParseRESTTaskListPage(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		ids   []string
		next  string
		valid bool
	}{
		{"empty list", `{"tasks":[]}`, []string{}, "", true},
		{"task ID aliases", `{"tasks":[{"id":"t1"},{"taskId":"t2"}]}`, []string{"t1", "t2"}, "", true},
		{"bare list", `[{"id":"t1"}]`, []string{"t1"}, "", true},
		{"next page", `{"tasks":[],"nextPageToken":"next"}`, []string{}, "next", true},
		{"RPC error", `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`, nil, "", false},
		{"missing list", `{"totalSize":42}`, nil, "", false},
		{"missing task ID", `{"tasks":[{}]}`, nil, "", false},
		{"null cursor", `{"tasks":[],"nextPageToken":null}`, []string{}, "", false},
		{"invalid JSON", `not json`, nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, next, valid := parseRESTTaskListPage([]byte(tt.body))
			if valid != tt.valid || next != tt.next || !reflect.DeepEqual(ids, tt.ids) {
				t.Fatalf("got ids=%v next=%q valid=%t, want ids=%v next=%q valid=%t",
					ids, next, valid, tt.ids, tt.next, tt.valid)
			}
		})
	}
}
