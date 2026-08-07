package sse

import (
	"strings"
	"testing"
)

// A small SSE reply must not cost the ceiling in memory. NewReaderSize used to
// allocate maxLine up front, so a large cap made every SSE read expensive.
func TestFirstData_DoesNotAllocateTheCapUpFront(t *testing.T) {
	body := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = FirstData(strings.NewReader(body), 32<<20)
		}
	})
	perOp := res.AllocedBytesPerOp()
	t.Logf("allocated %d bytes per FirstData call with a 32 MB cap", perOp)
	if perOp > 1<<20 {
		t.Errorf("a small SSE reply allocated %d bytes; the cap must not be paid up front", perOp)
	}
}

// A line larger than the initial buffer must still be readable, up to the cap.
func TestFirstData_GrowsBeyondTheInitialBuffer(t *testing.T) {
	big := strings.Repeat("x", 4<<20) // 4 MB, far past the 64 KB initial buffer
	body := "data: " + big + "\n\n"
	got, err := FirstData(strings.NewReader(body), 32<<20)
	if err != nil {
		t.Fatalf("FirstData: %v", err)
	}
	if len(got) != len(big) {
		t.Errorf("got %d bytes, want %d: the scanner must grow to the cap", len(got), len(big))
	}
}
