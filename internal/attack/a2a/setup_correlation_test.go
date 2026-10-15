package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestOwnerTaskSetupCorrelatesReplies(t *testing.T) {
	type creator func(context.Context, *attack.HTTPClient, string, attack.Principal, string) (string, setupObservation)
	creators := []struct {
		name string
		run  creator
	}{
		{"push binding", func(ctx context.Context, c *attack.HTTPClient, ep string, p attack.Principal, id string) (string, setupObservation) {
			return (&PushBindingExecutor{}).createTask(ctx, c, ep, p, id)
		}},
		{"task cancellation", func(ctx context.Context, c *attack.HTTPClient, ep string, p attack.Principal, id string) (string, setupObservation) {
			return (&TaskCancelIDORExecutor{}).createTask(ctx, c, ep, p, id)
		}},
		{"tenant isolation", func(ctx context.Context, c *attack.HTTPClient, ep string, p attack.Principal, id string) (string, setupObservation) {
			taskID, _, _, obs := (&MultiTenantIsolationExecutor{}).createTask(ctx, c, ep, p, id)
			return taskID, obs
		}},
		{"task enumeration", func(ctx context.Context, c *attack.HTTPClient, ep string, p attack.Principal, id string) (string, setupObservation) {
			return (&TaskEnumerationExecutor{}).createTask(ctx, c, ep, p, id)
		}},
	}
	for _, mode := range []string{"valid", "wrong result", "wrong error", "both wrong"} {
		for _, tc := range creators {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var req struct {
						ID     string `json:"id"`
						Method string `json:"method"`
					}
					if json.NewDecoder(r.Body).Decode(&req) != nil {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					id := req.ID
					if (req.Method == "SendMessage" && mode != "valid") ||
						(req.Method == "message/send" && mode == "both wrong") {
						id = "other-request"
					}
					w.Header().Set("Content-Type", "application/json")
					if req.Method == "SendMessage" && mode == "wrong error" {
						_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id,
							"error": map[string]any{"code": -32601, "message": "Method not found"}})
						return
					}
					if req.Method != "SendMessage" && req.Method != "message/send" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					taskID := "task-v1"
					if req.Method == "message/send" {
						taskID = "task-v03"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id,
						"result": map[string]string{"id": taskID}})
				}))
				defer srv.Close()

				vars := attack.NewVars(srv.URL, "")
				client := attack.NewHTTPClient(attack.Options{TimeoutSeconds: 5}, vars)
				principal := attack.Principal{Name: "owner", Headers: map[string]string{"Authorization": "Bearer owner"}}
				taskID, obs := tc.run(t.Context(), client, srv.URL, principal, "probe")
				switch mode {
				case "valid":
					if taskID != "task-v1" || obs.partialErr() != nil {
						t.Fatalf("valid v1 setup: task=%q partial=%v", taskID, obs.partialErr())
					}
				case "both wrong":
					if taskID != "" || !errors.Is(obs.err(), attack.ErrInconclusive) {
						t.Fatalf("unmatched setup must be incomplete: task=%q err=%v", taskID, obs.err())
					}
				default:
					if taskID != "task-v03" || !errors.Is(obs.partialErr(), attack.ErrInconclusive) {
						t.Fatalf("fallback must retain unjudged v1 reply: task=%q partial=%v", taskID, obs.partialErr())
					}
				}
			})
		}
	}
}
