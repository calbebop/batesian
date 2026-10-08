package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

var listCases = []struct {
	method string
	id     int
	key    string
	item   map[string]interface{}
	call   func(*Client, *Session) (int, error)
}{
	{"tools/list", 10, "tools", map[string]interface{}{"name": "tool"}, func(c *Client, s *Session) (int, error) {
		items, err := c.ListTools(context.Background(), s)
		return len(items), err
	}},
	{"resources/list", 11, "resources", map[string]interface{}{"uri": "file:///resource"}, func(c *Client, s *Session) (int, error) {
		items, err := c.ListResources(context.Background(), s)
		return len(items), err
	}},
	{"prompts/list", 12, "prompts", map[string]interface{}{"name": "prompt"}, func(c *Client, s *Session) (int, error) {
		items, err := c.ListPrompts(context.Background(), s)
		return len(items), err
	}},
}

func TestListMethodsFollowEmptyCursor(t *testing.T) {
	for _, tc := range listCases {
		for _, modern := range []bool{false, true} {
			name := tc.method + "/legacy"
			if modern {
				name = tc.method + "/modern"
			}
			t.Run(name, func(t *testing.T) {
				calls := 0
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var req struct {
						Method string                 `json:"method"`
						Params map[string]interface{} `json:"params"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Errorf("decode request: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if req.Method != tc.method {
						t.Errorf("method = %q, want %q", req.Method, tc.method)
					}
					cursor, present := req.Params["cursor"]
					if calls == 0 && present || calls == 1 && (!present || cursor != "") {
						t.Errorf("page %d cursor = %v, present = %t", calls+1, cursor, present)
					}
					calls++
					result := map[string]interface{}{tc.key: []interface{}{tc.item}}
					if modern {
						result["resultType"] = "complete"
					}
					if calls == 1 {
						result["nextCursor"] = ""
					} else {
						result["nextCursor"] = nil
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": tc.id, "result": result,
					})
				}))
				defer srv.Close()
				client, err := NewClient(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				count, err := tc.call(client, &Session{Endpoint: srv.URL, Modern: modern})
				if err != nil {
					t.Fatal(err)
				}
				if count != 2 || calls != 2 {
					t.Errorf("got %d items in %d calls, want 2 in 2", count, calls)
				}
			})
		}
	}
}

func TestListMethodsAcceptPageLimit(t *testing.T) {
	for _, tc := range listCases {
		t.Run(tc.method, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				result := map[string]interface{}{
					"resultType": "complete", tc.key: []interface{}{tc.item},
				}
				if calls < maxListPages {
					result["nextCursor"] = strconv.Itoa(calls)
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": tc.id, "result": result,
				})
			}))
			defer srv.Close()
			client, err := NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			count, err := tc.call(client, &Session{Endpoint: srv.URL, Modern: true})
			if err != nil || count != maxListPages || calls != maxListPages {
				t.Fatalf("got %d items in %d calls, error %v; want %d complete pages", count, calls, err, maxListPages)
			}
		})
	}
}

func TestListMethodsRejectIncompletePagination(t *testing.T) {
	for _, tc := range listCases {
		for _, mode := range []string{"limit", "repeated cursor", "RPC error", "missing items", "invalid cursor", "invalid entry"} {
			t.Run(tc.method+"/"+mode, func(t *testing.T) {
				calls := 0
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					result := map[string]interface{}{
						"resultType": "complete", tc.key: []interface{}{tc.item},
					}
					switch mode {
					case "limit":
						result["nextCursor"] = strconv.Itoa(calls)
					case "repeated cursor":
						result["nextCursor"] = ""
					case "RPC error":
						if calls == 1 {
							result["nextCursor"] = "next"
						} else {
							_ = json.NewEncoder(w).Encode(map[string]interface{}{
								"jsonrpc": "2.0", "id": tc.id,
								"error": map[string]interface{}{"code": -32602, "message": "Invalid cursor"},
							})
							return
						}
					case "missing items":
						delete(result, tc.key)
					case "invalid cursor":
						result["nextCursor"] = 42
					case "invalid entry":
						result[tc.key] = []interface{}{tc.item, "invalid"}
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": tc.id, "result": result,
					})
				}))
				defer srv.Close()
				client, err := NewClient(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				count, err := tc.call(client, &Session{Endpoint: srv.URL, Modern: true})
				if err == nil || count != 0 {
					t.Fatalf("got %d items, error %v; want an incomplete-inventory error", count, err)
				}
				if mode == "limit" && calls != maxListPages {
					t.Errorf("limit made %d calls, want %d", calls, maxListPages)
				}
				if mode == "repeated cursor" && calls != 2 {
					t.Errorf("repeated cursor made %d calls, want 2", calls)
				}
				if mode == "RPC error" && !strings.Contains(err.Error(), "Invalid cursor") {
					t.Errorf("RPC error lost its reason: %v", err)
				}
			})
		}
	}
}
