package retry

import (
	"context"
	"time"

	"github.com/sethvargo/go-retry"
)

var RetryableError = retry.RetryableError

const (
	baseDuration = 50 * time.Millisecond
	maxDuration  = 5 * time.Second
)

func fibonacci() retry.Backoff {
	b := retry.NewFibonacci(baseDuration)
	// beware: this starts a timer when invoked, on which the max duration is evaluated against
	b = retry.WithMaxDuration(maxDuration, b)
	return b
}

// Do retries the given function using the DefaultBackoff strategy.
func Do(ctx context.Context, f retry.RetryFunc) error {
	return retry.Do(ctx, fibonacci(), f)
}

// DoValue is like Do, but returns a value of type T.
func DoValue[T any](ctx context.Context, f retry.RetryFuncValue[T]) (T, error) {
	return retry.DoValue(ctx, fibonacci(), f)
}
