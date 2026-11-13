package a2a_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"iter"
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
	mu                        sync.Mutex
	tasks                     map[a2a.TaskID]*a2a.Task
	mode                      string
	calls                     int
	listCalls, subscribeCalls int
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
	owner := "A"
	if strings.Contains(task.History[0].Parts[0].Text(), "reader") {
		owner = "B"
	}
	publicTask := f.mode == "public" || strings.HasPrefix(f.mode, "reader-public") && owner == "B"
	if who == "" && !publicTask {
		return nil, a2a.ErrUnauthenticated
	}
	crossAllowed := f.mode == "vulnerable" || f.mode == "tls-vulnerable" || f.mode == "wrong-task" ||
		f.mode == "reader-to-owner" && who == "B" && owner == "A" ||
		f.mode == "owner-to-reader" && who == "A" && owner == "B" ||
		strings.HasPrefix(f.mode, "reader-public") && (owner == "B" || f.mode == "reader-public-forward-leak")
	if who != "" && who != owner && !crossAllowed {
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

func (f *grpcTaskFixture) ListTasks(ctx context.Context, req *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	f.mu.Lock()
	f.calls++
	f.listCalls++
	defer f.mu.Unlock()
	if !strings.HasPrefix(f.mode, "list-") {
		return nil, a2a.ErrMethodNotFound
	}
	who := grpcFixturePrincipal(ctx)
	if who == "" && f.mode != "list-public" && f.mode != "list-anon-id-only" {
		return nil, a2a.ErrUnauthenticated
	}
	if f.mode == "list-timeout" && who == "B" {
		f.mu.Unlock()
		<-ctx.Done()
		f.mu.Lock()
		return nil, ctx.Err()
	}
	if f.mode == "list-page-cap" && who == "B" {
		return &a2a.ListTasksResponse{Tasks: []*a2a.Task{}, NextPageToken: req.PageToken + "x"}, nil
	}
	if f.mode == "list-page-two" && who == "B" && req.PageToken == "" {
		return &a2a.ListTasksResponse{Tasks: []*a2a.Task{}, NextPageToken: "next"}, nil
	}
	var tasks []*a2a.Task
	for _, task := range f.tasks {
		owner := "A"
		if strings.Contains(task.History[0].Parts[0].Text(), "reader") {
			owner = "B"
		}
		visible := who == owner || f.mode == "list-public" || f.mode == "list-anon-id-only" && who == "" ||
			who == "B" && owner == "A" && (f.mode == "list-leak" || f.mode == "list-page-two" ||
				f.mode == "list-no-marker" || f.mode == "list-wrong-id" || f.mode == "list-anon-id-only")
		if !visible {
			continue
		}
		copy := *task
		if who == "" && f.mode == "list-anon-id-only" {
			copy.History = nil
		}
		if who == "B" && owner == "A" {
			if f.mode == "list-no-marker" {
				copy.History = nil
			}
			if f.mode == "list-wrong-id" {
				copy.ID = "other-task"
			}
		}
		tasks = append(tasks, &copy)
	}
	return &a2a.ListTasksResponse{Tasks: tasks, TotalSize: len(tasks), PageSize: req.PageSize}, nil
}

func (f *grpcTaskFixture) SubscribeToTask(ctx context.Context, req *a2a.SubscribeToTaskRequest) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		f.mu.Lock()
		f.calls++
		f.subscribeCalls++
		task := f.tasks[req.ID]
		f.mu.Unlock()
		if !strings.HasPrefix(f.mode, "subscribe-") {
			yield(nil, a2a.ErrMethodNotFound)
			return
		}
		if task == nil {
			yield(nil, a2a.ErrTaskNotFound)
			return
		}
		if f.mode == "subscribe-terminal" {
			yield(nil, a2a.ErrUnsupportedOperation)
			return
		}
		who := grpcFixturePrincipal(ctx)
		owner := "A"
		if strings.Contains(task.History[0].Parts[0].Text(), "reader") {
			owner = "B"
		}
		if who == "" && f.mode != "subscribe-public" {
			yield(nil, a2a.ErrUnauthenticated)
			return
		}
		crossSample := who == "B" && owner == "A" &&
			(f.mode == "subscribe-timeout" || f.mode == "subscribe-wrong-id" || f.mode == "subscribe-no-marker")
		if who != "" && who != owner && f.mode != "subscribe-leak" && !crossSample {
			yield(nil, a2a.ErrTaskNotFound)
			return
		}
		if f.mode == "subscribe-timeout" && who == "B" && owner == "A" {
			<-ctx.Done()
			yield(nil, ctx.Err())
			return
		}
		copy := *task
		if crossSample && f.mode == "subscribe-wrong-id" {
			copy.ID = "other-task"
		}
		if crossSample && f.mode == "subscribe-no-marker" {
			copy.History = nil
		}
		if f.mode == "subscribe-terminal-event" {
			copy.Status = a2a.TaskStatus{State: a2a.TaskStateCompleted}
		}
		yield(&copy, nil)
	}
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
		_ = json.NewEncoder(w).Encode(map[string]any{
			"supportedInterfaces": interfaces,
			"capabilities":        map[string]bool{"streaming": strings.HasPrefix(mode, "subscribe-")},
		})
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
		{"vulnerable", 2, false},
		{"reader-to-owner", 1, false},
		{"owner-to-reader", 1, false},
		{"tls-protected", 0, false},
		{"tls-vulnerable", 2, false},
		{"tls-untrusted", 0, true},
		{"header-auth", 0, false},
		{"public", 0, true},
		{"reader-public", 0, true},
		{"reader-public-forward-leak", 1, true},
		{"wrong-task", 1, true},
		{"redacted-owner", 0, true},
		{"reader-invalid", 0, true},
		{"unsupported", 0, true},
		{"card-mismatch", 0, true},
		{"card-scheme-mismatch", 0, true},
		{"card-path", 0, true},
		{"mixed-tenants", 0, true},
		{"list-protected", 0, false},
		{"list-leak", 1, false},
		{"list-anon-id-only", 1, false},
		{"list-page-two", 1, false},
		{"list-no-marker", 0, true},
		{"list-wrong-id", 0, false},
		{"list-public", 0, true},
		{"list-page-cap", 0, true},
		{"list-timeout", 0, true},
		{"subscribe-protected", 0, false},
		{"subscribe-leak", 2, false},
		{"subscribe-wrong-id", 0, true},
		{"subscribe-no-marker", 0, true},
		{"subscribe-terminal", 0, true},
		{"subscribe-terminal-event", 0, true},
		{"subscribe-public", 0, true},
		{"subscribe-timeout", 0, true},
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
			fixture.mu.Lock()
			var taskIDs []string
			for id := range fixture.tasks {
				taskIDs = append(taskIDs, string(id))
			}
			listCalls, subscribeCalls := fixture.listCalls, fixture.subscribeCalls
			fixture.mu.Unlock()
			if listCalls > 10 || subscribeCalls > 6 ||
				!strings.HasPrefix(tc.mode, "subscribe-") && subscribeCalls != 0 {
				t.Fatalf("unbounded or unadvertised calls: list=%d subscribe=%d", listCalls, subscribeCalls)
			}
			for _, finding := range findings {
				assertOpaqueTaskFinding(t, finding, append(taskIDs, "batesian grpc ")...)
				wantConfidence := attack.ConfirmedExploit
				wantAnonymous := "anonymous: denied"
				if strings.HasPrefix(tc.mode, "list-") {
					wantConfidence = attack.RiskIndicator
					wantAnonymous = "anonymous list: private marker absent or denied"
				}
				if strings.HasPrefix(tc.mode, "subscribe-") {
					wantAnonymous = "anonymous subscription: denied"
				}
				if finding.Confidence != wantConfidence || !strings.Contains(finding.Evidence, wantAnonymous) {
					t.Fatalf("finding lacked controls: %+v", finding)
				}
			}
			if tc.mode == "owner-to-reader" && !strings.Contains(findings[0].Evidence, "owner: reader (tenant B)") {
				t.Fatalf("reverse-direction finding missing: %+v", findings[0])
			}
			if tc.mode == "reader-to-owner" && !strings.Contains(findings[0].Evidence, "owner: owner (tenant A)") {
				t.Fatalf("forward-direction finding missing: %+v", findings[0])
			}
			if tc.mode == "reader-public-forward-leak" && !strings.Contains(findings[0].Evidence, "owner: owner (tenant A)") {
				t.Fatalf("public reverse task suppressed forward finding: %+v", findings[0])
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

func TestGRPCListExpectedDenial(t *testing.T) {
	target, grpcTarget, _, _ := newGRPCTaskFixture(t, "list-leak")
	findings, err := attacka2a.NewGRPCTaskAccessExecutor(attack.RuleContext{
		ID: "a2a-grpc-task-access-001", Name: "A2A gRPC Cross-Tenant Task Disclosure",
	}).Execute(t.Context(), target, attack.Options{
		A2AGRPCTarget: grpcTarget, TimeoutSeconds: 3,
		Principals: []attack.Principal{
			{Name: "owner", Tenant: "A", Token: "token-a"},
			{Name: "reader", Tenant: "B", Token: "token-b"},
		},
		ExpectedDenials: []attack.ExpectedDenial{{
			Operation: attack.A2ATasksList, Caller: "reader", CallerTenant: "B", Owner: "owner", OwnerTenant: "A",
		}},
	})
	if err != nil || len(findings) != 1 || findings[0].Confidence != attack.ConfirmedExploit ||
		findings[0].Severity != "medium" || !strings.Contains(findings[0].Evidence, "expected denial") {
		t.Fatalf("findings=%+v err=%v", findings, err)
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
	if err != nil || cardReads.Load() != 0 || len(recorder.Requests()) != 21 {
		t.Fatalf("dry run err=%v card reads=%d plan=%+v", err, cardReads.Load(), recorder.Requests())
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.calls != 0 {
		t.Fatalf("dry run sent %d gRPC calls", fixture.calls)
	}
}
