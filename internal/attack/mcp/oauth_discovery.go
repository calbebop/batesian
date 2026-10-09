package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

var oauthServerMetadataPaths = []string{
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration",
}

// readOAuthMetadata distinguishes an absent document from one that could not be read.
func readOAuthMetadata(ctx context.Context, client *attack.HTTPClient, baseURL, path string) (*attack.Response, string) {
	resp, err := client.GET(ctx, endpoint.AppendPath(baseURL, path), nil)
	if err != nil || resp == nil {
		return nil, path + " did not answer"
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return nil, ""
	}
	if !resp.IsSuccess() {
		return nil, fmt.Sprintf("%s returned HTTP %d", path, resp.StatusCode)
	}
	if !resp.IsJSON() {
		return nil, path + " returned invalid JSON"
	}
	return resp, ""
}

func oauthDiscoveryIncomplete(reasons []string) error {
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: OAuth metadata could not be checked: %s", attack.ErrInconclusive, strings.Join(reasons, "; "))
}

// discoverOAuthFields returns fields from one complete discovery document.
func discoverOAuthFields(ctx context.Context, client *attack.HTTPClient, baseURL string, fields ...string) (map[string]string, error) {
	var incomplete []string
	for _, path := range oauthServerMetadataPaths {
		resp, reason := readOAuthMetadata(ctx, client, baseURL, path)
		if reason != "" {
			incomplete = append(incomplete, reason)
			continue
		}
		if resp == nil {
			continue
		}
		values := make(map[string]string, len(fields))
		complete := true
		for _, field := range fields {
			value := resp.JSONField(field)
			if value == "" {
				complete = false
				break
			}
			values[field] = value
		}
		if !complete {
			continue
		}
		for _, field := range fields {
			if err := client.ValidateOAuthEndpoint(values[field]); err != nil {
				return nil, err
			}
		}
		return values, nil
	}
	return nil, oauthDiscoveryIncomplete(incomplete)
}
