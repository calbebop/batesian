package httpx

import (
	"strconv"
	"testing"
	"time"
)

func TestTimeoutDuration(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		want    time.Duration
		wantErr bool
	}{
		{name: "negative", seconds: -1, wantErr: true},
		{name: "zero", wantErr: true},
		{name: "one second", seconds: 1, want: time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TimeoutDuration(tc.seconds)
			if (err != nil) != tc.wantErr {
				t.Fatalf("TimeoutDuration(%d) error = %v, wantErr %v", tc.seconds, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("TimeoutDuration(%d) = %s, want %s", tc.seconds, got, tc.want)
			}
		})
	}

	if strconv.IntSize == 64 {
		max := maxTimeoutSeconds
		got, err := TimeoutDuration(int(max))
		if err != nil || got != time.Duration(max)*time.Second {
			t.Fatalf("TimeoutDuration(%d) = %s, %v", max, got, err)
		}

		tooLarge := max + 1
		if _, err := TimeoutDuration(int(tooLarge)); err == nil {
			t.Fatalf("TimeoutDuration(%d) succeeded", tooLarge)
		}
	}
}
