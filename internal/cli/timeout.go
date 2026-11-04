package cli

import (
	"fmt"
	"time"

	"github.com/calbebop/batesian/internal/httpx"
)

func requestTimeout(seconds int) (time.Duration, error) {
	timeout, err := httpx.TimeoutDuration(seconds)
	if err != nil {
		return 0, fmt.Errorf("--timeout %w", err)
	}
	return timeout, nil
}

func scanBudgetDuration(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return 0, nil
	}
	budget, err := httpx.TimeoutDuration(seconds)
	if err != nil {
		return 0, fmt.Errorf("--scan-budget %w", err)
	}
	return budget, nil
}
