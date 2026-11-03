package a2a_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2agrpc/v1"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/calbebop/batesian/internal/attack"
	attacka2a "github.com/calbebop/batesian/internal/attack/a2a"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

type grpcTaskFixture struct {
	a2asrv.RequestHandler
	mu    sync.Mutex
	tasks map[a2a.TaskID]*a2a.Task
	mode  string
	calls int
}

func (f *grpcTaskFixture) SendMessage(ctx context.Context, req *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	who := grpcFixturePrincipal(ctx)
	if who == "" || f.mode == "reader-invalid" && who == "B" {
		return nil, a2a.ErrUnauthenticated
	}
	if req == nil || req.Message == nil || len(req.Message.Parts) == 0 {
		return nil, a2a.ErrInvalidParams
	}
	task := a2a.NewSubmittedTask(req.Message, req.Message)
	f.mu.Lock()
	f.tasks[task.ID] = task
	f.mu.Unlock()
	return task, nil
}

func (f *grpcTaskFixture) GetTask(ctx context.Context, req *a2a.GetTaskRequest) (*a2a.Task, error) {
	who := grpcFixturePrincipal(ctx)
	f.mu.Lock()
	f.calls++
	task := f.tasks[req.ID]
	f.mu.Unlock()
	if task == nil {
		return nil, a2a.ErrTaskNotFound
	}
	if f.mode == "unsupported" {
		return nil, a2a.ErrUnsupportedOperation
	}
	if who == "" && f.mode != "public" {
		return nil, a2a.ErrUnauthenticated
	}
	owner := "A"
	if strings.Contains(task.History[0].Parts[0].Text(), "reader") {
		owner = "B"
	}
	if who != "" && who != owner && f.mode != "vulnerable" && f.mode != "tls-vulnerable" && f.mode != "wrong-task" {
		return nil, a2a.ErrTaskNotFound
	}
	copy := *task
	if f.mode == "wrong-task" && who == "B" && owner == "A" {
		copy.ID = "wrong-task-id"
	}
	if f.mode == "redacted-owner" && who == "A" && owner == "A" {
		copy.History = []*a2a.Message{a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("redacted"))}
	}
	return &copy, nil
}

func grpcFixturePrincipal(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if versions := md.Get("a2a-version"); len(versions) != 1 || versions[0] != "1.0" {
		return ""
	}
	switch strings.ToLower(strings.Join(md.Get("authorization"), "")) {
	case "bearer token-a":
		return "A"
	case "bearer token-b":
		return "B"
	default:
		switch strings.Join(md.Get("x-tenant-id"), "") {
		case "A":
			return "A"
		case "B":
			return "B"
		default:
			return ""
		}
	}
}

func newGRPCTaskFixture(t *testing.T, mode string) (string, string, *grpcTaskFixture, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &grpcTaskFixture{tasks: make(map[a2a.TaskID]*a2a.Task), mode: mode}
	var serverOptions []grpc.ServerOption
	if strings.HasPrefix(mode, "tls-") {
		certServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		certificate := certServer.TLS.Certificates[0]
		certServer.Close()
		serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
		})))
	}
	grpcServer := grpc.NewServer(serverOptions...)
	a2agrpc.NewHandler(fixture).RegisterWith(grpcServer)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() { grpcServer.Stop(); _ = listener.Close() })
	cardReads := &atomic.Int32{}
	cardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cardReads.Add(1)
		if r.URL.Path != "/.well-known/agent-card.json" {
			http.NotFound(w, r)
			return
		}
		address := "http://" + listener.Addr().String()
		if strings.HasPrefix(mode, "tls-") {
			address = "https://" + listener.Addr().String()
		}
		if mode == "card-mismatch" {
			address = "http://127.0.0.1:1"
		}
		if mode == "card-scheme-mismatch" {
			address = "https://" + listener.Addr().String()
		}
		if mode == "card-path" {
			address = "http://" + listener.Addr().String() + "/a2a"
		}
		interfaces := []any{map[string]string{"protocolBinding": "GRPC", "protocolVersion": "1.0", "url": address}}
		if mode == "mixed-tenants" {
			interfaces = append(interfaces, map[string]string{
				"protocolBinding": "GRPC", "protocolVersion": "1.0", "url": address, "tenant": "A",
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"supportedInterfaces": interfaces})
	}))
	t.Cleanup(cardServer.Close)
	scheme := "grpc://"
	if strings.HasPrefix(mode, "tls-") {
		scheme = "grpcs://"
	}
	return cardServer.URL, scheme + listener.Addr().String(), fixture, cardReads
}

func TestGRPCTaskAccessOfficialSDK(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		findings     int
		inconclusive bool
	}{
		{"protected", 0, false},
		{"vulnerable", 1, false},
		{"tls-protected", 0, false},
		{"tls-vulnerable", 1, false},
		{"tls-untrusted", 0, true},
		{"header-auth", 0, false},
		{"public", 0, true},
		{"wrong-task", 0, true},
		{"redacted-owner", 0, true},
		{"reader-invalid", 0, true},
		{"unsupported", 0, true},
		{"card-mismatch", 0, true},
		{"card-scheme-mismatch", 0, true},
		{"card-path", 0, true},
		{"mixed-tenants", 0, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			target, grpcTarget, fixture, _ := newGRPCTaskFixture(t, tc.mode)
			principals := []attack.Principal{
				{Name: "owner", Tenant: "A", Token: "token-a"},
				{Name: "reader", Tenant: "B", Token: "token-b"},
			}
			if tc.mode == "header-auth" {
				principals[0].Token, principals[1].Token = "", ""
				principals[0].Headers = map[string]string{"X-Tenant-Id": "A"}
				principals[1].Headers = map[string]string{"X-Tenant-Id": "B"}
			}
			findings, err := attacka2a.NewGRPCTaskAccessExecutor(attack.RuleContext{
				ID: "a2a-grpc-task-access-001", Name: "A2A gRPC Cross-Tenant Task Disclosure", Remediation: "Check task ownership on every GetTask call.",
			}).Execute(t.Context(), target, attack.Options{
				A2AGRPCTarget: grpcTarget, TimeoutSeconds: 3,
				Principals: principals,
				SkipTLS:    tc.mode == "tls-protected" || tc.mode == "tls-vulnerable",
			})
			if len(findings) != tc.findings || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				err != nil && !tc.inconclusive {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			if tc.findings == 1 && (findings[0].Confidence != attack.ConfirmedExploit ||
				!strings.Contains(findings[0].Evidence, "anonymous: denied")) {
				t.Fatalf("finding lacked controls: %+v", findings[0])
			}
			if tc.mode == "card-mismatch" || tc.mode == "card-scheme-mismatch" ||
				tc.mode == "card-path" || tc.mode == "mixed-tenants" {
				fixture.mu.Lock()
				calls := fixture.calls
				fixture.mu.Unlock()
				if calls != 0 {
					t.Fatalf("gRPC calls sent despite rejected card: %d", calls)
				}
			}
		})
	}
}

func TestGRPCTaskAccessDryRunSendsNothing(t *testing.T) {
	target, grpcTarget, fixture, cardReads := newGRPCTaskFixture(t, "vulnerable")
	recorder := &attack.Recorder{}
	_, err := attacka2a.NewGRPCTaskAccessExecutor(attack.RuleContext{}).Execute(t.Context(), target, attack.Options{
		A2AGRPCTarget: grpcTarget, DryRun: true, Recorder: recorder,
		Principals: []attack.Principal{
			{Name: "owner", Tenant: "A", Token: "token-a"},
			{Name: "reader", Tenant: "B", Token: "token-b"},
		},
	})
	if err != nil || cardReads.Load() != 0 || len(recorder.Requests()) != 7 {
		t.Fatalf("dry run err=%v card reads=%d plan=%+v", err, cardReads.Load(), recorder.Requests())
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.calls != 0 {
		t.Fatalf("dry run sent %d gRPC calls", fixture.calls)
	}
}
