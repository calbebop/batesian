package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/calbebop/batesian/internal/attack"
)

const crossoverRounds = 3
const maxCrossoverPairs = 3

type ResponseCrossoverExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-response-crossover", func(rc attack.RuleContext) attack.Executor {
		return &ResponseCrossoverExecutor{rule: rc}
	})
}

func NewResponseCrossoverExecutor(rc attack.RuleContext) *ResponseCrossoverExecutor {
	return &ResponseCrossoverExecutor{rule: rc}
}

func (e *ResponseCrossoverExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	owner, caller, err := crossoverPrincipals(opts)
	if err != nil {
		return nil, err
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	ownerClient := attack.NewUnauthHTTPClient(opts, vars)
	callerClient := attack.NewUnauthHTTPClient(opts, vars)
	var session mcpSession
	for _, endpoint := range modernDiscoveryEndpoints(vars.BaseURL, "") {
		candidate := mcpSession{Endpoint: endpoint, Era: EraModern}
		a, aErr := cacheScopeFetch(ctx, ownerClient, candidate, owner, 1, cacheSurface{method: "server/discover"})
		b, bErr := cacheScopeFetch(ctx, callerClient, candidate, caller, 2, cacheSurface{method: "server/discover"})
		if aErr == nil && bErr == nil && modernWireAdvertised(a.raw) && modernWireAdvertised(b.raw) &&
			cacheSupports(a.raw, "resources") && cacheSupports(b.raw, "resources") {
			session = candidate
			break
		}
	}
	if session.Endpoint == "" {
		return nil, fmt.Errorf("%w: two principals could not discover the same modern resource endpoint",
			attack.ErrInconclusive)
	}
	list := cacheSurface{method: "resources/list", field: "resources", page: 1}
	aList, aErr := cacheScopeFetch(ctx, ownerClient, session, owner, 10, list)
	bList, bErr := cacheScopeFetch(ctx, callerClient, session, caller, 11, list)
	if aErr != nil || bErr != nil {
		return nil, fmt.Errorf("%w: both principals need readable resource lists", attack.ErrInconclusive)
	}
	aPages, aPageErr := cacheResourcePages(ctx, ownerClient, session, owner, aList, 20)
	bPages, bPageErr := cacheResourcePages(ctx, callerClient, session, caller, bList, 30)
	ownerURIs := sampleResourceURIs(aPages)
	callerURIs := sampleResourceURIs(bPages)
	if len(ownerURIs) == 0 || len(callerURIs) == 0 {
		return nil, errors.Join(aPageErr, bPageErr, fmt.Errorf("%w: both principals need listed resources",
			attack.ErrInconclusive))
	}
	var incomplete []error
	if aPageErr != nil {
		incomplete = append(incomplete, aPageErr)
	}
	if bPageErr != nil {
		incomplete = append(incomplete, bPageErr)
	}
	controlled := false
	pairCount := 0
	for i, ownerURI := range ownerURIs {
		ownerRead := cacheSurface{method: "resources/read", field: "contents", params: map[string]interface{}{"uri": ownerURI}}
		a1, aErr := cacheScopeFetch(ctx, ownerClient, session, owner, 100+4*i, ownerRead)
		a2, aRepeatErr := cacheScopeFetch(ctx, ownerClient, session, owner, 101+4*i, ownerRead)
		ownerContent := crossoverContent(a1)
		if aErr != nil || aRepeatErr != nil || ownerContent == nil || !bytes.Equal(ownerContent, crossoverContent(a2)) {
			continue
		}
		if !mrtrPost(ctx, callerClient, session, caller, 102+4*i, "resources/read", ownerRead.params).denied {
			continue
		}
		for j, callerURI := range callerURIs {
			if callerURI == ownerURI {
				continue
			}
			callerRead := cacheSurface{method: "resources/read", field: "contents", params: map[string]interface{}{"uri": callerURI}}
			b1, bErr := cacheScopeFetch(ctx, callerClient, session, caller, 200+4*j, callerRead)
			b2, bRepeatErr := cacheScopeFetch(ctx, callerClient, session, caller, 201+4*j, callerRead)
			callerContent := crossoverContent(b1)
			if bErr != nil || bRepeatErr != nil || callerContent == nil ||
				!bytes.Equal(callerContent, crossoverContent(b2)) || bytes.Equal(callerContent, ownerContent) {
				continue
			}
			controlled = true
			pairCount++
			completeRounds := 0
			for round := range crossoverRounds {
				ownerReply, crossed := crossoverPair(ctx, ownerClient, callerClient, session, owner, caller,
					ownerRead, callerRead, 500+round)
				crossedContent := crossoverContent(crossed)
				if !bytes.Equal(crossedContent, ownerContent) {
					if crossoverContent(ownerReply) != nil && crossedContent != nil {
						completeRounds++
					}
					continue
				}
				ownerAfter, ownerErr := cacheScopeFetch(ctx, ownerClient, session, owner, 600, ownerRead)
				callerAfter, callerErr := cacheScopeFetch(ctx, callerClient, session, caller, 601, callerRead)
				if ownerErr != nil || callerErr != nil || !bytes.Equal(crossoverContent(ownerAfter), ownerContent) ||
					!bytes.Equal(crossoverContent(callerAfter), callerContent) ||
					!mrtrPost(ctx, callerClient, session, caller, 602, "resources/read", ownerRead.params).denied {
					incomplete = append(incomplete, fmt.Errorf("%w: resource controls changed after a concurrent response",
						attack.ErrInconclusive))
					continue
				}
				return []attack.Finding{{
					RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.ConfirmedExploit,
					Title:       "MCP response crossed between authenticated clients",
					Description: fmt.Sprintf("%s was denied a read of %s's resource, but received that resource's content while concurrently requesting its own resource with the same JSON-RPC ID. Keep each HTTP response bound to its originating request and authorization context.", caller.name, owner.name),
					Evidence: fmt.Sprintf("wire: MCP %s\nowner: %s\ncaller: %s\ncaller read of owner resource: denied before and after\nsequential resource contents: stable and distinct\nconcurrent caller response: matched owner content\nresource URIs and content omitted",
						modernEraVersion, owner.name, caller.name),
					Remediation: e.rule.Remediation, TargetURL: session.Endpoint,
				}}, errors.Join(incomplete...)
			}
			if completeRounds != crossoverRounds {
				incomplete = append(incomplete, fmt.Errorf("%w: concurrent resource reads did not both return comparable results",
					attack.ErrInconclusive))
			}
			if pairCount == maxCrossoverPairs {
				return nil, errors.Join(incomplete...)
			}
		}
	}
	if !controlled {
		incomplete = append(incomplete, fmt.Errorf("%w: no stable, distinct resource pair with a denied cross-principal read",
			attack.ErrInconclusive))
	}
	return nil, errors.Join(incomplete...)
}

func crossoverPrincipals(opts attack.Options) (taskPrincipal, taskPrincipal, error) {
	if len(opts.Principals) < 2 {
		return taskPrincipal{}, taskPrincipal{}, fmt.Errorf("%w: response crossover requires two configured principals",
			attack.ErrInconclusive)
	}
	a, err := configuredTaskPrincipal(opts.Principals[0])
	if err != nil {
		return a, taskPrincipal{}, err
	}
	b, err := configuredTaskPrincipal(opts.Principals[1])
	if err != nil {
		return a, b, err
	}
	if len(principalIdentityHeaders(a)) == 0 || len(principalIdentityHeaders(b)) == 0 || samePrincipalIdentity(a, b) {
		return a, b, fmt.Errorf("%w: response crossover requires two distinct principal identities",
			attack.ErrInconclusive)
	}
	return a, b, nil
}

func crossoverContent(snapshot cacheSnapshot) []byte {
	envelope, ok := parseResponseBody(snapshot.raw)
	if !ok {
		return nil
	}
	result, _ := envelope["result"].(map[string]interface{})
	return mrtrContents(result)
}

func crossoverPair(ctx context.Context, ownerClient, callerClient *attack.HTTPClient, session mcpSession,
	owner, caller taskPrincipal, ownerRead, callerRead cacheSurface, id int) (cacheSnapshot, cacheSnapshot) {
	var ownerReply, callerReply cacheSnapshot
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		ownerReply, _ = cacheScopeFetch(ctx, ownerClient, session, owner, id, ownerRead)
	}()
	go func() {
		defer wg.Done()
		<-start
		callerReply, _ = cacheScopeFetch(ctx, callerClient, session, caller, id, callerRead)
	}()
	close(start)
	wg.Wait()
	return ownerReply, callerReply
}
