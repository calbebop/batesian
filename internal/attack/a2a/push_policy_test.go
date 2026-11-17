package a2a_test

import (
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func TestPushBindingExpectedDenials(t *testing.T) {
	for _, tc := range []struct {
		name, mode, version string
		want                []attack.AccessObservation
	}{
		{"jsonrpc-anonymous", "open", "", []attack.AccessObservation{
			{Operation: attack.A2APushConfigsWrite, Caller: "anonymous", Owner: "tenant-a", OwnerTenant: "A"},
		}},
		{"jsonrpc-cross", "unbound", "", []attack.AccessObservation{
			{Operation: attack.A2APushConfigsRead, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"},
			{Operation: attack.A2APushConfigsWrite, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"},
		}},
		{"rest-v1-anonymous", "anonymous-write", "1.0", []attack.AccessObservation{
			{Operation: attack.A2APushConfigsWrite, Caller: "anonymous", Owner: "tenant-a", OwnerTenant: "A"},
		}},
		{"rest-v1-read", "cross-read", "1.0", []attack.AccessObservation{
			{Operation: attack.A2APushConfigsRead, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"},
		}},
		{"rest-v03-write", "cross-write", "0.3.0", []attack.AccessObservation{
			{Operation: attack.A2APushConfigsWrite, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var findings []attack.Finding
			if tc.version == "" {
				server := pushServer(tc.mode)
				defer server.Close()
				findings = runPushBinding(t, server, pushPrincipals())
			} else {
				server := pushBindingRESTServer(tc.version, tc.mode)
				defer server.Close()
				var err error
				findings, err = a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
					attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals()})
				if err != nil {
					t.Fatal(err)
				}
			}
			assertPushPolicy(t, findings, tc.want)
		})
	}
}

func TestPushLifecycleExpectedDenials(t *testing.T) {
	want := []attack.AccessObservation{
		{Operation: attack.A2APushConfigsList, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"},
		{Operation: attack.A2APushConfigsDelete, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"},
		{Operation: attack.A2APushConfigsList, Caller: "tenant-a", CallerTenant: "A", Owner: "tenant-b", OwnerTenant: "B"},
		{Operation: attack.A2APushConfigsDelete, Caller: "tenant-a", CallerTenant: "A", Owner: "tenant-b", OwnerTenant: "B"},
	}
	for _, version := range []string{"jsonrpc", "1.0", "0.3.0"} {
		t.Run(version, func(t *testing.T) {
			var findings []attack.Finding
			var err error
			if version == "jsonrpc" {
				server := pushServer("lifecycle-open")
				defer server.Close()
				findings, err = a2a.NewPushLifecycleExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
					attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals()})
			} else {
				server := pushLifecycleRESTServer(version, "open")
				defer server.Close()
				findings, err = a2a.NewPushLifecycleExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
					attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals()})
			}
			if err != nil {
				t.Fatal(err)
			}
			assertPushPolicy(t, findings, want)
		})
	}
}

func assertPushPolicy(t *testing.T, findings []attack.Finding, want []attack.AccessObservation) {
	t.Helper()
	if len(findings) != len(want) {
		t.Fatalf("findings = %+v, want %d", findings, len(want))
	}
	remaining := append([]attack.AccessObservation(nil), want...)
	for _, finding := range findings {
		if finding.Access == nil || finding.Confidence != attack.RiskIndicator {
			t.Fatalf("finding lacks indicator access: %+v", finding)
		}
		match := -1
		for i, expected := range remaining {
			if *finding.Access == expected {
				match = i
				break
			}
		}
		if match < 0 {
			t.Fatalf("unexpected access: %+v", finding.Access)
		}
		remaining = append(remaining[:match], remaining[match+1:]...)
		policy := attack.ExpectedDenial{
			Operation: finding.Access.Operation, Caller: finding.Access.Caller,
			CallerTenant: finding.Access.CallerTenant, Owner: finding.Access.Owner,
			OwnerTenant: finding.Access.OwnerTenant,
		}
		for _, wrong := range []attack.ExpectedDenial{
			{Operation: attack.A2ATasksCancel, Caller: policy.Caller, Owner: policy.Owner},
			{Operation: policy.Operation, Caller: policy.Owner, Owner: policy.Caller},
			{Operation: policy.Operation, Caller: policy.Caller, Owner: policy.Owner, OwnerTenant: "other"},
		} {
			unchanged := finding
			if attack.ApplyExpectedDenial(&unchanged, []attack.ExpectedDenial{wrong}) || unchanged.Confidence != attack.RiskIndicator {
				t.Fatalf("unrelated policy promoted finding: %+v", wrong)
			}
		}
		if !attack.ApplyExpectedDenial(&finding, []attack.ExpectedDenial{policy}) ||
			finding.Confidence != attack.ConfirmedExploit || !strings.Contains(finding.Evidence, "expected denial:") {
			t.Fatalf("matching policy did not confirm finding: %+v", finding)
		}
	}
}
