package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestDCRCleanupAfterScanCancellation(t *testing.T) {
	auth := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		auth <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 2}, attack.NewVars(ts.URL, ""))
	registration := &attack.Response{
		StatusCode: http.StatusCreated,
		Body: []byte(fmt.Sprintf(`{"registration_client_uri":%q,"registration_access_token":"rat-test"}`,
			ts.URL+"/register/client-1")),
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cleanup := deregisterDCRClient(ctx, client, ts.URL+"/register", "batesian-test", registration)
	if cleanup.status != attack.CleanupCompleted {
		t.Fatalf("cleanup after cancellation = %+v", cleanup)
	}
	select {
	case got := <-auth:
		if got != "Bearer rat-test" {
			t.Fatalf("DELETE authorization = %q", got)
		}
	default:
		t.Fatal("cleanup sent no DELETE")
	}
}
