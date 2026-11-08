package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// DCR probes may register clients on the target. RFC 7592 cleanup is attempted
// when the server returns a management URI and access token.

// dcrCleanup records whether a registered client was removed.
type dcrCleanup struct {
	clientName string
	status     attack.CleanupStatus
	// reason is why the client could not be removed, empty when it was.
	reason string
}

// evidenceLine names the client so an operator can find it if cleanup failed.
func (c dcrCleanup) evidenceLine() string {
	if c.clientName == "" {
		return ""
	}
	switch c.status {
	case attack.CleanupCompleted:
		return fmt.Sprintf("client registered by this probe (%s): deleted afterwards via RFC 7592\n", c.clientName)
	case attack.CleanupAttempted:
		return fmt.Sprintf("client registered by this probe (%s): cleanup attempted but not confirmed, %s; "+
			"verify its status on the target\n", c.clientName, c.reason)
	case attack.CleanupNotAttempted:
		return fmt.Sprintf("client registered by this probe (%s): cleanup not attempted, %s; "+
			"verify its status on the target\n", c.clientName, c.reason)
	}
	return fmt.Sprintf("client registered by this probe (%s): cleanup unavailable, %s; "+
		"the client may remain on the target\n", c.clientName, c.reason)
}

func recordDCRState(state *attack.TargetState, endpoint, clientName string, reg *attack.Response, cleanup dcrCleanup) {
	if reg == nil || (reg.StatusCode != http.StatusOK && reg.StatusCode != http.StatusCreated) {
		return
	}
	state.Record(attack.TargetObject{
		Kind:          "oauth_client",
		Creation:      "accepted",
		ID:            reg.JSONField("client_id"),
		Name:          clientName,
		Endpoint:      endpoint,
		Cleanup:       cleanup.status,
		CleanupDetail: cleanup.reason,
	})
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
	out := dcrCleanup{clientName: clientName, status: attack.CleanupUnavailable}
	if reg == nil {
		out.reason = "the registration produced no response to read a management URI from"
		return out
	}
	if reg.StatusCode != http.StatusOK && reg.StatusCode != http.StatusCreated {
		out.reason = "the registration was not confirmed"
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

	if !sameOrigin(clientURI, registrationEndpoint) {
		out.reason = fmt.Sprintf("its registration_client_uri points at %s while registration "+
			"happened at %s, and a target-chosen URI on another origin is not followed",
			hostOrInvalid(clientURI), hostOrInvalid(registrationEndpoint))
		return out
	}

	out.status = attack.CleanupAttempted
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	resp, err := client.DELETEOAuth(cleanupCtx, clientURI, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if err != nil {
		out.reason = "the delete request did not complete"
		return out
	}
	if resp.StatusCode == http.StatusNoContent {
		out.status = attack.CleanupCompleted
		return out
	}
	if resp.IsSuccess() {
		out.reason = fmt.Sprintf("the delete returned HTTP %d rather than RFC 7592's 204", resp.StatusCode)
		return out
	}
	out.reason = fmt.Sprintf("the delete was refused with HTTP %d", resp.StatusCode)
	return out
}

// sameOrigin reports whether two URLs share an HTTP(S) scheme, host, and
// effective port, without credentials or fragments.
func sameOrigin(a, b string) bool {
	ua, erra := url.Parse(a)
	ub, errb := url.Parse(b)
	if erra != nil || errb != nil || ua.Host == "" || ub.Host == "" ||
		ua.User != nil || ub.User != nil || ua.Fragment != "" || ub.Fragment != "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Hostname(), ub.Hostname()) &&
		effectivePort(ua) == effectivePort(ub)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func hostOrInvalid(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<invalid URI>"
	}
	return u.Host
}
