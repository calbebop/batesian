package httpx

import (
	"fmt"
	"time"
)

const maxTimeoutSeconds int64 = (1<<63 - 1) / int64(time.Second)

// TimeoutDuration converts positive seconds without overflowing time.Duration.
func TimeoutDuration(seconds int) (time.Duration, error) {
	if seconds <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	if int64(seconds) > maxTimeoutSeconds {
		return 0, fmt.Errorf("must not exceed %d seconds", maxTimeoutSeconds)
	}
	return time.Duration(seconds) * time.Second, nil
}
