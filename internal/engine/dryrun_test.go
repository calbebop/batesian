package engine

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/rules"
)

// TestEngineDryRunSendsNothing runs every bundled rule through the engine in
// dry-run mode against a listener that flags any accepted connection, and asserts
// that no rule dialed the target while requests were still recorded. This is the
// end-to-end proof that every scan-path HTTP client (including the two rules that
// build their own client) routes through the non-dialing dry-run transport.
func TestEngineDryRunSendsNothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var dialed int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.StoreInt32(&dialed, 1)
			conn.Close()
		}
	}()
	target := "http://" + ln.Addr().String()

	rs, _, err := rules.LoadDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(rs) == 0 {
		t.Fatal("no rules loaded from ../../rules")
	}

	rec := &attackpkg.Recorder{}
	opts := attackpkg.Options{
		DryRun:         true,
		Recorder:       rec,
		Token:          "dummy-token",
		TimeoutSeconds: 2,
		// Two principals so the multi-tenant and handoff rules exercise their
		// full request sequence rather than skipping for lack of identities.
		Principals: []attackpkg.Principal{
			{Name: "tenant-a", Token: "tok-a", Tenant: "A"},
			{Name: "tenant-b", Token: "tok-b", Tenant: "B"},
		},
	}
	New(opts).Run(context.Background(), target, rs)

	if atomic.LoadInt32(&dialed) != 0 {
		t.Fatal("dry run dialed the target; a scan-path client bypassed the dry-run transport")
	}
	if len(rec.Requests()) == 0 {
		t.Fatal("dry run recorded no requests; executors did not issue any traffic")
	}
}
