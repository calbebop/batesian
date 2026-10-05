package a2a

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/calbebop/batesian/internal/attack"
)

type tenantRoutesKey struct{}

type tenantRoute struct {
	base    string
	tenant  *string
	binding string
}

type tenantRoutes struct {
	mu     sync.RWMutex
	routes []tenantRoute
}

func withTenantRouting(ctx context.Context) context.Context {
	routes := &tenantRoutes{}
	ctx = context.WithValue(ctx, tenantRoutesKey{}, routes)
	return attack.WithRequestAugmenter(ctx, routes.augment)
}

func registerTenantRoute(ctx context.Context, base, binding string, tenant *string) {
	routes, ok := ctx.Value(tenantRoutesKey{}).(*tenantRoutes)
	if !ok {
		return
	}
	routes.mu.Lock()
	defer routes.mu.Unlock()
	for i := range routes.routes {
		if routes.routes[i].base == base && routes.routes[i].binding == binding {
			routes.routes[i].tenant = tenant
			return
		}
	}
	routes.routes = append(routes.routes, tenantRoute{base: base, binding: binding, tenant: tenant})
}

func (r *tenantRoutes) augment(method, requestURL string, headers map[string]string, body interface{}) (map[string]string, interface{}) {
	if !isA2AV1(headers) {
		return nil, body
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if method == http.MethodPost && isJSONRPCRequest(body) {
		for _, route := range r.routes {
			if route.binding == "JSONRPC" && route.base == requestURL && route.tenant != nil {
				return nil, withJSONRPCTenant(body, *route.tenant)
			}
		}
		return nil, body
	}
	var selected *tenantRoute
	for i := range r.routes {
		route := &r.routes[i]
		if route.binding == "HTTP+JSON" && routeContains(route.base, requestURL) &&
			(selected == nil || len(route.base) > len(selected.base)) {
			selected = route
		}
	}
	if selected == nil || selected.tenant == nil {
		return nil, body
	}
	if method == http.MethodGet {
		return map[string]string{"tenant": *selected.tenant}, body
	}
	if method == http.MethodPost {
		if request, ok := body.(map[string]interface{}); ok {
			copy := make(map[string]interface{}, len(request)+1)
			for key, value := range request {
				copy[key] = value
			}
			copy["tenant"] = *selected.tenant
			return nil, copy
		}
	}
	return nil, body
}

func isA2AV1(headers map[string]string) bool {
	for key, value := range headers {
		if strings.EqualFold(key, "A2A-Version") && value == "1.0" {
			return true
		}
	}
	return false
}

func isJSONRPCRequest(body interface{}) bool {
	switch request := body.(type) {
	case map[string]interface{}:
		_, ok := request["jsonrpc"]
		return ok
	case []interface{}:
		return len(request) > 0 && isJSONRPCRequest(request[0])
	}
	return false
}

func withJSONRPCTenant(body interface{}, tenant string) interface{} {
	switch request := body.(type) {
	case map[string]interface{}:
		method, _ := request["method"].(string)
		if method == "" || strings.Contains(method, "/") {
			return body
		}
		copy := make(map[string]interface{}, len(request))
		for key, value := range request {
			copy[key] = value
		}
		params, _ := request["params"].(map[string]interface{})
		paramsCopy := make(map[string]interface{}, len(params)+1)
		for key, value := range params {
			paramsCopy[key] = value
		}
		paramsCopy["tenant"] = tenant
		copy["params"] = paramsCopy
		return copy
	case []interface{}:
		copy := make([]interface{}, len(request))
		for i, item := range request {
			copy[i] = withJSONRPCTenant(item, tenant)
		}
		return copy
	}
	return body
}

func routeContains(base, requestURL string) bool {
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	u, err := url.Parse(requestURL)
	if err != nil || !strings.EqualFold(b.Scheme, u.Scheme) || !strings.EqualFold(b.Host, u.Host) {
		return false
	}
	path := strings.TrimSuffix(b.Path, "/")
	return u.Path == path || strings.HasPrefix(u.Path, path+"/")
}
