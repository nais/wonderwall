package retry

import (
	"time"

	"github.com/sethvargo/go-retry"
)

const (
	DefaultBaseDuration = 50 * time.Millisecond
	DefaultMaxDuration  = 1 * time.Second
)

var DefaultBackoff = Fibonacci().Backoff()

type FibonacciBackoff struct {
	base    time.Duration
	max     time.Duration
	backoff retry.Backoff
}

func (in *FibonacciBackoff) BaseDuration(base time.Duration) {
	in.base = base
	in.backoff = fibonacci(in.base, in.max)
}

func (in *FibonacciBackoff) MaxDuration(max time.Duration) {
	in.max = max
	in.backoff = fibonacci(in.base, in.max)
}

func (in *FibonacciBackoff) Backoff() retry.Backoff {
	return in.backoff
}

func Fibonacci() *FibonacciBackoff {
	return &FibonacciBackoff{
		base:    DefaultBaseDuration,
		max:     DefaultMaxDuration,
		backoff: fibonacci(DefaultBaseDuration, DefaultMaxDuration),
	}
}

func fibonacci(base, max time.Duration) retry.Backoff {
	b := retry.NewFibonacci(base)
	b = retry.WithMaxDuration(max, b)
	return b
}
