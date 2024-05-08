package retry

import (
	"context"
	"time"

	"github.com/sethvargo/go-retry"
)

var (
	DefaultBackoff = Fibonacci()
	RetryableError = retry.RetryableError
)

type FibonacciBackoff struct {
	Base time.Duration
	Max  time.Duration
}

func WithBaseDuration(base time.Duration) func(*FibonacciBackoff) {
	return func(f *FibonacciBackoff) {
		f.Base = base
	}
}

func WithMaxDuration(max time.Duration) func(*FibonacciBackoff) {
	return func(f *FibonacciBackoff) {
		f.Max = max
	}
}

func Fibonacci(opts ...func(f *FibonacciBackoff)) retry.Backoff {
	const DefaultBaseDuration = 50 * time.Millisecond
	const DefaultMaxDuration = 1 * time.Second

	fb := &FibonacciBackoff{
		Base: DefaultBaseDuration,
		Max:  DefaultMaxDuration,
	}

	for _, opt := range opts {
		opt(fb)
	}

	b := retry.NewFibonacci(fb.Base)
	b = retry.WithMaxDuration(fb.Max, b)
	return b
}

// Do retries the given function using the DefaultBackoff strategy.
func Do(ctx context.Context, f retry.RetryFunc) error {
	return DoWithBackoff(ctx, DefaultBackoff, f)
}

// DoWithBackoff retries the given function using the given backoff strategy.
func DoWithBackoff(ctx context.Context, b retry.Backoff, f retry.RetryFunc) error {
	return retry.Do(ctx, b, f)
}
