package a2a

import "testing"

func TestRestVersionHeaders(t *testing.T) {
	extra := map[string]string{"a2a-version": "0.3", "Authorization": "Bearer owner"}
	v1 := restVersionHeaders("1.0", extra)
	if v1["A2A-Version"] != "1.0" || v1["a2a-version"] != "" || v1["Authorization"] != "Bearer owner" {
		t.Fatalf("v1 headers=%v", v1)
	}
	legacy := restVersionHeaders("0.3.0", extra)
	if legacy["A2A-Version"] != "" || legacy["a2a-version"] != "" || legacy["Authorization"] != "Bearer owner" {
		t.Fatalf("v0.3 headers=%v", legacy)
	}
	if extra["a2a-version"] != "0.3" {
		t.Fatalf("input headers changed: %v", extra)
	}
}
