package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// Three rules register an OAuth client on the target, and none of them removed it.
// A scan against an authorization server with open dynamic client registration
// therefore left three clients behind, permanently:
//
//	mcp-confused-deputy-001     a client whose redirect_uri points off-origin, which
//	                            is the attacker-shaped value the rule exists to see
//	                            accepted
//	mcp-oauth-dcr-001           a client holding whatever privileged scopes the
//	                            server was willing to grant an anonymous registrant
//	mcp-oauth-metadata-ssrf-001 a client whose metadata URL fields point at the
//	                            scan's OOB listener, a host that stops existing when
//	                            the scan ends
//
// That is a scanner changing the state of the system it was pointed at and not
// changing it back. RFC 7592 is the way back: a registration response MAY carry a
// registration_client_uri and a registration_access_token, and a DELETE to that URI
// with that token deregisters the client.

// dcrCleanup is what happened to a client this scan registered. It is reported in
// the finding's evidence, because an operator who authorized a scan needs to know
// whether it left anything behind, and if so what to look for.
type dcrCleanup struct {
	clientName string
	deleted    bool
	// reason is why the client could not be removed, empty when it was.
	reason string
}

// evidenceLine renders the outcome for a finding's evidence. It names the client
// either way: on success so the record is complete, and on failure so the operator
// has the string to search their authorization server for.
func (c dcrCleanup) evidenceLine() string {
	if c.clientName == "" {
		return ""
	}
	if c.deleted {
		return fmt.Sprintf("client registered by this probe (%s): deleted afterwards via RFC 7592\n", c.clientName)
	}
	return fmt.Sprintf("client registered by this probe (%s): LEFT REGISTERED on the target, %s; "+
		"remove it by hand\n", c.clientName, c.reason)
}

// deregisterDCRClient removes a client this scan registered, following RFC 7592.
//
// Best effort by design: a server that does not implement the management protocol
// cannot be cleaned up, and that is a fact to report rather than an error to fail
// on. The rule's own verdict never depends on this.
//
// The URI is the SERVER'S to choose, so it is only followed when it stays on the
// registration endpoint's host. Following a target-chosen absolute URL to another
// host would make the scanner issue requests wherever the target pointed it, which
// is the same class of mistake as sending the operator's token off-host (see
// tokenAllowedFor). The token sent here is the registration_access_token the target
// itself just issued, not the operator's credential.
func deregisterDCRClient(ctx context.Context, client *attack.HTTPClient,
	registrationEndpoint, clientName string, reg *attack.Response) dcrCleanup {
	out := dcrCleanup{clientName: clientName}
	if reg == nil {
		out.reason = "the registration produced no response to read a management URI from"
		return out
	}

	clientURI := reg.JSONField("registration_client_uri")
	accessToken := reg.JSONField("registration_access_token")
	switch {
	case clientURI == "" && accessToken == "":
		out.reason = "the server returned neither registration_client_uri nor " +
			"registration_access_token, so it does not implement RFC 7592 client management"
		return out
	case clientURI == "":
		out.reason = "the server returned no registration_client_uri, so there is no " +
			"documented address to delete the client at"
		return out
	case accessToken == "":
		out.reason = "the server returned no registration_access_token, so a delete would " +
			"be unauthenticated"
		return out
	}

	if !sameHost(clientURI, registrationEndpoint) {
		out.reason = fmt.Sprintf("its registration_client_uri points at %s while registration "+
			"happened at %s, and a target-chosen URI on another host is not followed",
			hostOrRaw(clientURI), hostOrRaw(registrationEndpoint))
		return out
	}

	resp, err := client.DELETE(ctx, clientURI, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if err != nil {
		out.reason = "the delete request failed: " + err.Error()
		return out
	}
	// RFC 7592 section 2.3 specifies 204 on success. Accept any 2xx: implementations
	// answer 200 with a body, and 202 when deletion is queued.
	if resp.IsSuccess() || resp.StatusCode == http.StatusNoContent {
		out.deleted = true
		return out
	}
	out.reason = fmt.Sprintf("the delete was refused with HTTP %d", resp.StatusCode)
	return out
}

// sameHost reports whether two URLs share a host, case-insensitively.
func sameHost(a, b string) bool {
	ua, erra := url.Parse(a)
	ub, errb := url.Parse(b)
	if erra != nil || errb != nil || ua.Host == "" || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Host, ub.Host)
}

// hostOrRaw returns a URL's host for use in a message, falling back to the raw
// string so an unparseable value is still shown rather than dropped.
func hostOrRaw(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}
