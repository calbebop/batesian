package auth

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestBrowserLaunchCommands(t *testing.T) {
	url := "https://auth.example.com/authorize?client_id=batesian&redirect_uri=https%3A%2F%2F127.0.0.1%3A9&scope=mcp%3Aread+openid&state=st1&code_challenge=abc&code_challenge_method=S256"
	for _, tc := range []struct {
		platform string
		wantArgs []string
	}{
		{"windows", []string{"rundll32", "url.dll,FileProtocolHandler", url}},
		{"darwin", []string{"open", url}},
		{"linux", []string{"xdg-open", url}},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			called := false
			err := openInBrowserWith(url, tc.platform, func(cmd *exec.Cmd) error {
				called = true
				if len(cmd.Args) != len(tc.wantArgs) {
					t.Fatalf("launch args = %q, want %q", cmd.Args, tc.wantArgs)
				}
				for i, want := range tc.wantArgs {
					if cmd.Args[i] != want {
						t.Fatalf("launch arg %d = %q, want %q", i, cmd.Args[i], want)
					}
				}
				if strings.Contains(strings.ToLower(cmd.Path), "cmd") {
					t.Fatalf("browser launch routes through a shell: %q", cmd.Path)
				}
				return nil
			})
			if err != nil || !called {
				t.Fatalf("browser launch was not attempted: called=%t err=%v", called, err)
			}
		})
	}
}

func TestBrowserLaunchRejectsInvalidURL(t *testing.T) {
	for _, target := range []string{"http://auth.example.com/authorize", "not-a-url"} {
		called := false
		err := openInBrowserWith(target, "windows", func(*exec.Cmd) error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Fatalf("invalid URL must not launch: target=%q called=%t err=%v", target, called, err)
		}
	}
}

func TestBrowserLaunchReturnsStartError(t *testing.T) {
	want := errors.New("start failed")
	err := openInBrowserWith("https://auth.example.com/authorize", "windows", func(*exec.Cmd) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("launch error = %v, want %v", err, want)
	}
}
