package auth_test

import (
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/auth"
)

// TestWindowsBrowserCmd_PreservesAmpersands pins the regression behind the
// rundll32 switch: cmd /c start without shell-quoting treated & in the
// authorization URL as a command separator, truncating what opened and
// leaking the remainder of the line to whatever followed. The rundll32 form
// carries the URL as one raw CreateProcess argument, so every metacharacter
// must survive verbatim - asserted here on any platform, since command
// construction no longer depends on running Windows to be inspectable.
func TestWindowsBrowserCmd_PreservesAmpersands(t *testing.T) {
	url := "https://auth.example.com/authorize?client_id=batesian&redirect_uri=https%3A%2F%2F127.0.0.1%3A9&scope=mcp%3Aread+openid&state=st1&code_challenge=abc&code_challenge_method=S256"

	cmd := auth.WindowsBrowserCmd(url)

	if len(cmd.Args) != 3 {
		t.Fatalf("want exactly [rundll32 url.dll,FileProtocolHandler <url>], got %+v", cmd.Args)
	}
	if cmd.Args[0] != "rundll32" || !strings.HasPrefix(cmd.Args[1], "url.dll,FileProtocolHandler") {
		t.Fatalf("unexpected dispatch form: %+v", cmd.Args)
	}
	got := cmd.Args[2]
	if got != url {
		t.Fatalf("URL mutated in transit:\n want %q\n got  %q", url, got)
	}
	for _, metachar := range []string{"&", "?"} {
		if !strings.Contains(got, metachar) {
			t.Errorf("metachar %q missing from constructed argument; quoting reintroduced the truncation bug", metachar)
		}
	}
}

// TestWindowsBrowserCmd_NoShellInPath guards against re-routing through
// cmd.exe: everything before the URL must be rundll32 itself, since any
// intermediate shell would reinterpret & and ? before rundll32 ever sees them.
func TestWindowsBrowserCmd_NoShellInPath(t *testing.T) {
	cmd := auth.WindowsBrowserCmd("https://x.example/?a=1&b=2")
	if strings.Contains(strings.ToLower(cmd.Path), "cmd") {
		t.Fatalf("launch path routes through cmd.exe again: %q", cmd.Path)
	}
}
