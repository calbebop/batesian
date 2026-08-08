package a2a

import (
	"errors"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// All five cross-principal rules answered this precondition with nil,nil, which
// means "tested, and the target is secure". They send no packets in that state, so
// a default scan with no --principal flags reported 5 of 17 A2A rules clean without
// touching the target.
func TestTwoPrincipals(t *testing.T) {
	t.Run("none configured", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("want ErrInconclusive, got %v", err)
		}
		if !strings.Contains(err.Error(), "--principal") {
			t.Errorf("the reason should tell the operator how to make the rule run, got: %v", err)
		}
	})

	t.Run("only one configured", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{{Name: "a", Token: "t"}}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("want ErrInconclusive, got %v", err)
		}
	})

	t.Run("two sharing a token is one identity", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "same"}, {Name: "b", Token: "same"},
		}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("want ErrInconclusive, got %v", err)
		}
		// The reason has to name them, or an operator cannot tell which two.
		if !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), `"b"`) {
			t.Errorf("the reason should name both principals, got: %v", err)
		}
	})

	t.Run("two distinct identities run", func(t *testing.T) {
		a, b, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "tok-a"}, {Name: "b", Token: "tok-b"},
		}})
		if err != nil {
			t.Fatalf("two distinct principals must be accepted: %v", err)
		}
		if a.Name != "a" || b.Name != "b" {
			t.Errorf("returned the wrong pair: %q and %q", a.Name, b.Name)
		}
	})

	t.Run("a third principal is ignored, not an error", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "1"}, {Name: "b", Token: "2"}, {Name: "c", Token: "3"},
		}})
		if err != nil {
			t.Errorf("extra principals are ignored by these rules, not rejected: %v", err)
		}
	})
}
