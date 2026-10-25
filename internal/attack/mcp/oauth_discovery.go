package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

var oauthServerMetadataPaths = []string{
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration",
}

// readOAuthMetadata distinguishes an absent document from one that could not be read.
func readOAuthMetadata(ctx context.Context, client *attack.HTTPClient, baseURL, path string) (*attack.Response, string) {
	var incomplete []string
	for _, metadataURL := range oauthWellKnownURLs(baseURL, path) {
		resp, err := client.GETOAuthUnauth(ctx, metadataURL)
		if err != nil || resp == nil {
			incomplete = append(incomplete, metadataURL+" did not answer")
			continue
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			continue
		}
		if !resp.IsSuccess() {
			incomplete = append(incomplete, fmt.Sprintf("%s returned HTTP %d", metadataURL, resp.StatusCode))
			continue
		}
		if !resp.IsJSON() {
			incomplete = append(incomplete, metadataURL+" returned invalid JSON")
			continue
		}
		return resp, ""
	}
	return nil, strings.Join(incomplete, "; ")
}

func oauthWellKnownURLs(baseURL, wellKnownPath string) []string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	if wellKnownPath == "/.well-known/oauth-protected-resource" {
		seen := map[string]bool{}
		var urls []string
		for _, candidate := range endpointCandidates(baseURL) {
			parsed, err := url.Parse(candidate)
			if err != nil || parsed.EscapedPath() == "" || parsed.EscapedPath() == "/" {
				continue
			}
			metadataURL := origin + wellKnownPath + strings.TrimSuffix(parsed.EscapedPath(), "/")
			if !seen[metadataURL] {
				seen[metadataURL] = true
				urls = append(urls, metadataURL)
			}
		}
		return append(urls, origin+wellKnownPath)
	}
	resourcePath := strings.TrimSuffix(u.EscapedPath(), "/")
	var urls []string
	if resourcePath != "" {
		urls = append(urls, origin+wellKnownPath+resourcePath)
	}
	urls = append(urls, origin+wellKnownPath)
	if resourcePath != "" && wellKnownPath == "/.well-known/openid-configuration" {
		urls = append(urls, origin+resourcePath+wellKnownPath)
	}
	return urls
}

func oauthDiscoveryIncomplete(reasons []string) error {
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: OAuth metadata could not be checked: %s", attack.ErrInconclusive, strings.Join(reasons, "; "))
}

// discoverOAuthFields follows protected-resource metadata when available.
func discoverOAuthFields(ctx context.Context, client *attack.HTTPClient, baseURL string, fields ...string) (map[string]string, error) {
	var incomplete []string
	var resource *attack.Response
	if advertised, _, _ := probeWWWAuthenticateResourceMetadata(ctx, client, baseURL); advertised != "" {
		resp, err := client.GETOAuthUnauth(ctx, advertised)
		if err != nil || resp == nil {
			return nil, fmt.Errorf("%w: advertised protected-resource metadata could not be read", attack.ErrInconclusive)
		}
		if !resp.IsSuccess() || !resp.IsJSON() {
			return nil, fmt.Errorf("%w: advertised protected-resource metadata returned HTTP %d or invalid JSON", attack.ErrInconclusive, resp.StatusCode)
		}
		resource = resp
	} else {
		var reason string
		resource, reason = readOAuthMetadata(ctx, client, baseURL, "/.well-known/oauth-protected-resource")
		if reason != "" {
			incomplete = append(incomplete, reason)
		}
	}
	if resource != nil {
		var metadata struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		if json.Unmarshal(resource.Body, &metadata) != nil || !prmMatchesTarget(baseURL, metadata.Resource, resource.URL) || len(metadata.AuthorizationServers) == 0 {
			return nil, fmt.Errorf("%w: protected-resource metadata does not identify this resource and its authorization servers", attack.ErrInconclusive)
		}
		for _, issuer := range metadata.AuthorizationServers {
			if err := client.ValidateOAuthEndpoint(issuer); err != nil {
				incomplete = append(incomplete, "advertised authorization server is invalid or outside authorized OAuth origins; use --oauth-origin for a trusted issuer")
				continue
			}
			values, reasons, err := discoverIssuerFields(ctx, client, issuer, true, fields...)
			if err != nil {
				incomplete = append(incomplete, err.Error())
				continue
			}
			if values != nil {
				return values, nil
			}
			incomplete = append(incomplete, reasons...)
		}
		if len(incomplete) == 0 {
			incomplete = append(incomplete, "advertised authorization-server metadata is unavailable or lacks required fields")
		}
		return nil, oauthDiscoveryIncomplete(incomplete)
	}
	values, reasons, err := discoverIssuerFields(ctx, client, baseURL, false, fields...)
	if err != nil {
		return nil, err
	}
	incomplete = append(incomplete, reasons...)
	return values, oauthDiscoveryIncomplete(incomplete)
}

func prmMatchesTarget(targetURL, resourceURL, metadataURL string) bool {
	target, targetErr := url.Parse(targetURL)
	resource, resourceErr := url.Parse(resourceURL)
	metadata, metadataErr := url.Parse(metadataURL)
	if targetErr != nil || resourceErr != nil || metadataErr != nil || !resource.IsAbs() || resource.Host == "" || resource.User != nil || resource.Fragment != "" {
		return false
	}
	if !strings.EqualFold(target.Scheme, resource.Scheme) || !strings.EqualFold(target.Host, resource.Host) {
		return false
	}
	const prefix = "/.well-known/oauth-protected-resource"
	if strings.HasPrefix(metadata.Path, prefix) {
		if metadataPath := strings.TrimPrefix(metadata.Path, prefix); metadataPath != "" && metadataPath != resource.Path {
			return false
		}
	}
	if target.Path == "" || target.Path == "/" {
		return true
	}
	for _, candidate := range endpointCandidates(targetURL) {
		if candidate == resourceURL {
			return true
		}
	}
	return false
}

func discoverIssuerFields(ctx context.Context, client *attack.HTTPClient, issuer string, checkIssuer bool, fields ...string) (map[string]string, []string, error) {
	var incomplete []string
	for _, path := range oauthServerMetadataPaths {
		resp, reason := readOAuthMetadata(ctx, client, issuer, path)
		if reason != "" {
			incomplete = append(incomplete, reason)
			continue
		}
		if resp == nil {
			continue
		}
		if checkIssuer && resp.JSONField("issuer") != issuer {
			incomplete = append(incomplete, path+" issuer does not match the advertised authorization server")
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
				return nil, incomplete, fmt.Errorf("%w: authorization-server metadata contains an invalid or unapproved %s", attack.ErrInconclusive, field)
			}
		}
		return values, nil, nil
	}
	return nil, incomplete, nil
}
