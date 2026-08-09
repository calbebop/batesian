package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/calbebop/batesian/internal/attack"
)

// SessionAsCredentialExecutor tests whether an MCP server accepts its own
// Mcp-Session-Id as proof of identity (rule mcp-session-as-credential-001).
//
// The Security Best Practices are explicit, and the second sentence is what this
// rule tests: "MCP servers that implement authorization MUST verify all inbound
// requests. MCP Servers MUST NOT use sessions for authentication."
//
// Note the condition on the first sentence. The requirement binds on servers that
// implement authorization, so the rule has to establish that the server enforces
// authorization at all before it can accuse it of authenticating by session. That
// is what the unauthenticated control does; without it, a server with no
// authorization anywhere would be reported here instead of by
// mcp-tools-unauth-001, which owns that failure.
//
// The oracle is a pair of requests that differ in one detail. Both carry no
// credential. One presents a session id the server issued, the other a random id
// it never issued. If the first is answered and the second refused, the session id
// alone authorized the call. That is the exploit performed rather than inferred,
// and it is the spec's own Session Hijack Impersonation flow: anyone who reads a
// session id out of a proxy log replays the authenticated session.
type SessionAsCredentialExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-session-as-credential", func(rc attack.RuleContext) attack.Executor {
		return NewSessionAsCredentialExecutor(rc)
	})
}

func NewSessionAsCredentialExecutor(r attack.RuleContext) *SessionAsCredentialExecutor {
	return &SessionAsCredentialExecutor{rule: r}
}

func (e *SessionAsCredentialExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	// A credential is the premise: the rule asks whether a session id can stand in
	// for one, which cannot be asked without a working credential to compare
	// against. Reporting clean without one would claim the server was tested.
	token := credentialFor(opts)
	if token == "" {
		return nil, fmt.Errorf("%w: this rule needs one working credential, to establish a session "+
			"that a later request can then present without it; pass --token or a principal",
			attack.ErrInconclusive)
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	// No ambient token: every request here states its own credentials, because the
	// whole measurement is which requests carry one.
	client := attack.NewUnauthHTTPClient(opts, vars)

	authed := map[string]string{"Authorization": "Bearer " + token}

	// Why no candidate could be exercised. The credential is this rule's premise, so
	// the most likely failure is that the one it was given is not accepted, and
	// saying "could not reach a testable endpoint" about a server that answered and
	// refused it sends the operator to the wrong place.
	var observed initObservation
	findings, err := probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		// Step 1: handshake with the credential and capture the session id.
		session, ok, resp := e.initialize(ctx, client, ep, authed)
		if !ok {
			if resp != nil {
				observed.observe(classifyInitFailure(ep, true, resp))
			}
			return nil, false // not a reachable MCP endpoint
		}
		if session == "" {
			// Stateless, or a 2026-07-28 server, which removed protocol-level
			// sessions. There is no session id to misuse.
			return nil, true
		}

		// Step 2: the session must actually work when presented with the credential,
		// or there is nothing to strip.
		if v := e.toolsList(ctx, client, ep, session, authed); v != accessGranted {
			if v == accessUndetermined {
				observed.observe(initObservation{rankStatusOnly, fmt.Sprintf(
					"the credentialled call presenting the server's own session id at %s returned "+
						"neither a result nor a refusal, so the session was never shown to work and "+
						"there was nothing to strip", ep)})
				return nil, false
			}
			return nil, true
		}

		// Step 3: control. Does this server implement authorization at all? The
		// requirement is conditional on that, so it has to be established rather than
		// assumed.
		//
		// Measured against the official MCP C# SDK's stateful sample, which has no
		// authorization: it demands a session id for every non-initialize request and
		// answers one without it with -32000 "A new session can only be created by an
		// initialize request". So a request lacking a session is refused for SESSION
		// reasons, and the later controls cannot tell that apart from a refusal for
		// missing credentials. Every one of them passed and the rule reported a
		// false positive on a server that authenticates nothing.
		//
		// An anonymous handshake settles it, but the handshake alone does not: plenty
		// of servers leave initialize ungated and authorize the calls that follow, and
		// reading an open handshake as "no authorization" would suppress exactly the
		// servers this rule exists to find. What answers the question is whether the
		// session the anonymous caller was given can then call tools/list.
		var anonSession string
		if s, anonOK, _ := e.initialize(ctx, client, ep, nil); anonOK {
			anonSession = s
			if anonSession == "" {
				// It handshakes anonymously but issues this caller no session, so there
				// is no anonymous session to compare against, and a refusal below cannot
				// be attributed to the missing credential rather than the missing
				// session. Report nothing rather than guess.
				return nil, true
			}
			switch e.toolsList(ctx, client, ep, anonSession, nil) {
			case accessGranted:
				// A caller who presented no credential at any point reads the tool list.
				// The server implements no authorization, the MUST NOT above does not
				// bind on it, and mcp-tools-unauth-001 owns that surface.
				return nil, true
			case accessUndetermined:
				observed.observe(initObservation{rankStatusOnly, fmt.Sprintf(
					"the anonymous-session control at %s returned neither a result nor a refusal, so "+
						"whether this server authorizes anything could not be established", ep)})
				return nil, false
			}
			// The anonymous session was refused while the credentialed one was
			// accepted, on the same call with the same headers. That is the asymmetry
			// this rule reports, and it is stronger evidence than the never-issued-id
			// control below: both ids were minted by this server, and the only
			// difference between them is the credential presented when they were
			// opened.
		}

		// Step 4: control. No session, no credential. A server that answers this is
		// open on the surface under test, so a later success cannot be attributed to
		// the session id.
		switch e.toolsList(ctx, client, ep, "", nil) {
		case accessGranted:
			return nil, true
		case accessUndetermined:
			observed.observe(initObservation{rankStatusOnly, fmt.Sprintf(
				"the no-session no-credential control at %s returned neither a result nor a "+
					"refusal, so whether this surface is simply open could not be established",
				ep)})
			return nil, false
		}

		// Step 5: control. A random never-issued session id, no credential. A server
		// that accepts this treats the presence of the header as authorization, so the
		// issued id was not what decided it.
		bogus := "batesian-never-issued-" + vars.RandID
		switch e.toolsList(ctx, client, ep, bogus, nil) {
		case accessGranted:
			return nil, true
		case accessUndetermined:
			observed.observe(initObservation{rankStatusOnly, fmt.Sprintf(
				"the never-issued session-id control at %s returned neither a result nor a refusal, "+
					"so whether the server accepts any session id could not be established", ep)})
			return nil, false
		}

		// Step 6: the real session id, no credential.
		switch e.toolsList(ctx, client, ep, session, nil) {
		case accessRefused:
			return nil, true // the session carries no authority: secure
		case accessUndetermined:
			observed.observe(initObservation{rankStatusOnly, fmt.Sprintf(
				"the credential-stripped call presenting the real session id at %s returned neither "+
					"a result nor a refusal, so whether the session alone authorizes was never "+
					"observed", ep)})
			return nil, false
		}

		return []attack.Finding{e.finding(ep, session, bogus, anonSession)}, true
	})
	if errors.Is(err, attack.ErrInconclusive) && observed.rank > rankNothing {
		return nil, inconclusive(handshakeRefusal{observed.reason})
	}
	return findings, err
}

// credentialFor returns the credential to establish the session with, preferring
// an explicit principal so a multi-principal scan behaves predictably.
func credentialFor(opts attack.Options) string {
	for _, p := range opts.Principals {
		if p.Token != "" {
			return p.Token
		}
	}
	return opts.Token
}

// initialize performs the handshake and returns the session id the server minted,
// which is empty when the server assigns none.
// The response is returned alongside the verdict so a walk that established no
// session can say why. It is nil when nothing answered.
func (e *SessionAsCredentialExecutor) initialize(ctx context.Context, client *attack.HTTPClient,
	endpoint string, headers map[string]string) (session string, ok bool, resp *attack.Response) {
	resp, err := client.POST(ctx, endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": latestStable,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": attack.Version},
		},
	})
	if err != nil {
		return "", false, nil
	}
	if !resp.IsAccepted() {
		return "", false, resp
	}
	return resp.Headers.Get("Mcp-Session-Id"), true, resp
}

// toolsList reports whether tools/list was answered with a result under the given
// session id and headers. An empty session omits the header entirely.
//
// It requires a result envelope, not merely a 2xx: a server refusing the call with
// a JSON-RPC error at HTTP 200 has refused it, and reading that as success is the
// mistake that produced fabricated findings elsewhere in this package.
func (e *SessionAsCredentialExecutor) toolsList(ctx context.Context, client *attack.HTTPClient,
	endpoint, session string, headers map[string]string) accessVerdict {
	h := map[string]string{"Mcp-Protocol-Version": latestStable}
	for k, v := range headers {
		h[k] = v
	}
	if session != "" {
		h["Mcp-Session-Id"] = session
	}
	resp, err := client.POST(ctx, endpoint, h, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})
	// classifyAccess, not err != nil -> false. Steps 4 and 5 are SUPPRESSION controls,
	// so "refused" is the direction that lets the finding through: a transport failure
	// or a 429 on either of them used to read as "this server does gate the surface",
	// and the rule then attributed a step-6 success to the session id.
	verdict := classifyAccess(resp, err)
	// One session-specific amendment. HTTP 404 is the shape the transport prescribes
	// for a missing or unknown session id, and it commonly carries no JSON-RPC body, so
	// classifyAccess grades it undetermined. Here it is a real refusal: every call this
	// helper makes goes to an endpoint that has already completed a handshake, so a 404
	// is this server declining this request rather than a path that does not exist.
	// Without this a compliant server reports not tested at the controls instead of
	// being assessed.
	if verdict == accessUndetermined && resp != nil && resp.StatusCode == http.StatusNotFound {
		return accessRefused
	}
	return verdict
}

func (e *SessionAsCredentialExecutor) finding(endpoint, session, bogus, anonSession string) attack.Finding {
	// The anonymous-handshake control reads differently depending on how the server
	// answered it, and both readings are evidence, so state which one happened
	// rather than asserting a refusal that may not have been the one observed.
	anonLine := "initialize with no credential: refused, so the handshake is gated\n"
	if anonSession != "" {
		anonLine = fmt.Sprintf("tools/list with a session issued to an ANONYMOUS handshake (%s) "+
			"and no credential: refused\n", anonSession)
	}
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP server accepts its session ID as a credential (session used for authentication)",
		Description: fmt.Sprintf(
			"tools/list at %s was answered for a request carrying no credential, on the strength of "+
				"the Mcp-Session-Id the server itself issued. The same request presenting a session id "+
				"the server never issued was refused, and an unauthenticated request with no session at "+
				"all was refused, so authorization is enforced and the session id is what satisfied it. "+
				"The Security Best Practices require that servers implementing authorization verify all "+
				"inbound requests and state that servers MUST NOT use sessions for authentication. A "+
				"session id is a plaintext header logged by every proxy in the path, so anyone who reads "+
				"one replays the authenticated session.", endpoint),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nsession id issued to the credentialed handshake: %s\n"+
				"tools/list with session + credential: answered\n"+
				"%s"+
				"tools/list with no session and no credential: refused\n"+
				"tools/list with a never-issued session id (%s) and no credential: refused\n"+
				"tools/list with the issued session id and NO credential: answered",
			endpoint, session, anonLine, bogus),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
