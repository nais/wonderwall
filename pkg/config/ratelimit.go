package config

import (
	"time"

	flag "github.com/spf13/pflag"
)

type RateLimit struct {
	Enabled bool          `json:"enabled"`
	Logins  int           `json:"logins"`
	Window  time.Duration `json:"window"`
}

const (
	RateLimitEnabled = "ratelimit.enabled"
	RateLimitLogins  = "ratelimit.logins"
	RateLimitWindow  = "ratelimit.window"
)

func rateLimitFlags() {
	flag.Bool(RateLimitEnabled, true, "Enable rate limiting per user-agent.")
	flag.Int(RateLimitLogins, 5, "Maximum permitted login attempts within 'ratelimit.window' before rate limiting.")
	flag.Duration(RateLimitWindow, 5*time.Second, "Time window for counting consecutive attempts towards rate limit."+
		"Each attempt within the window will increment the attempt counter and reset the window."+
		"If the window expires with no additional attempts, the counter is discarded.")
}
