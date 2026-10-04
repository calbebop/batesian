package mcp

import (
	"errors"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestPrincipalIdentity(t *testing.T) {
	checks := []struct {
		name string
		fn   func(attack.Options) (taskPrincipal, taskPrincipal, error)
	}{
		{"task IDOR", taskPrincipals},
		{"scope confusion", scopePrincipals},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			tests := []struct {
				name         string
				principals   []attack.Principal
				inconclusive bool
			}{
				{
					name: "authorization override hides distinct tokens",
					principals: []attack.Principal{
						{Name: "a", Token: "token-a", Headers: map[string]string{"Authorization": "Bearer shared"}},
						{Name: "b", Token: "token-b", Headers: map[string]string{"authorization": "bearer  shared"}},
					},
					inconclusive: true,
				},
				{
					name: "header names are case insensitive",
					principals: []attack.Principal{
						{Name: "a", Headers: map[string]string{"X-API-Key": "shared"}},
						{Name: "b", Headers: map[string]string{"x-api-key": "shared"}},
					},
					inconclusive: true,
				},
				{
					name: "empty authorization overrides bearer token",
					principals: []attack.Principal{
						{Name: "a", Token: "token-a", Headers: map[string]string{"authorization": ""}},
						{Name: "b", Token: "token-b"},
					},
					inconclusive: true,
				},
				{
					name: "anonymous principal is not a second credential",
					principals: []attack.Principal{
						{Name: "a"}, {Name: "b", Token: "token-b"},
					},
					inconclusive: true,
				},
				{
					name: "distinct header credentials",
					principals: []attack.Principal{
						{Name: "a", Headers: map[string]string{"X-API-Key": "key-a"}},
						{Name: "b", Headers: map[string]string{"X-API-Key": "key-b"}},
					},
				},
				{
					name: "shared token with distinct routing headers",
					principals: []attack.Principal{
						{Name: "a", Token: "shared", Headers: map[string]string{"X-Tenant-Id": "A"}},
						{Name: "b", Token: "shared", Headers: map[string]string{"X-Tenant-Id": "B"}},
					},
				},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, _, err := check.fn(attack.Options{Principals: tt.principals})
					if got := errors.Is(err, attack.ErrInconclusive); got != tt.inconclusive {
						t.Fatalf("inconclusive=%t, want %t; err=%v", got, tt.inconclusive, err)
					}
					if !tt.inconclusive && err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestPrincipalHeaderNormalization(t *testing.T) {
	p, err := configuredTaskPrincipal(attack.Principal{
		Name: "a", Token: "original", Headers: map[string]string{"authorization": "Bearer override"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := map[string]string{}
	attachPrincipal(h, p)
	if len(h) != 1 || h["Authorization"] != "Bearer override" {
		t.Fatalf("custom Authorization must override the token deterministically, got %+v", h)
	}

	_, err = configuredTaskPrincipal(attack.Principal{
		Name: "a", Headers: map[string]string{
			"Authorization": "Bearer first", "authorization": "Bearer second",
		},
	})
	if !errors.Is(err, attack.ErrInconclusive) || strings.Contains(err.Error(), "Bearer ") {
		t.Fatalf("conflicting header names must be inconclusive without leaking values, got %v", err)
	}
}
