package retry

import (
	"context"
	"time"

	"github.com/sethvargo/go-retry"
)

var RetryableError = retry.RetryableError

type fibonacci struct {
	base time.Duration
	max  time.Duration
}

type Option func(*fibonacci)

func WithBase(d time.Duration) Option {
	return func(f *fibonacci) {
		f.base = d
	}
}

func WithMax(d time.Duration) Option {
	return func(f *fibonacci) {
		f.max = d
	}
}

func Do(ctx context.Context, f retry.RetryFunc, opts ...Option) error {
	return retry.Do(ctx, fibonacciBackoff(opts...), f)
}

func DoValue[T any](ctx context.Context, f retry.RetryFuncValue[T], opts ...Option) (T, error) {
	return retry.DoValue(ctx, fibonacciBackoff(opts...), f)
}

func fibonacciBackoff(opts ...Option) retry.Backoff {
	f := &fibonacci{
		base: 50 * time.Millisecond,
		max:  5 * time.Second,
	}

	for _, opt := range opts {
		opt(f)
	}

	b := retry.NewFibonacci(f.base)
	// beware: this starts a timer when invoked, on which the max duration is evaluated against
	b = retry.WithMaxDuration(f.max, b)
	return b
}
