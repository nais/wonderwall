package config

import (
	"time"

	flag "github.com/spf13/pflag"
)

type Session struct {
	ForwardAuth       bool          `json:"forward-auth"`
	Inactivity        bool          `json:"inactivity"`
	InactivityTimeout time.Duration `json:"inactivity-timeout"`
	MaxLifetime       time.Duration `json:"max-lifetime"`
}

const (
	SessionForwardAuth       = "session.forward-auth"
	SessionInactivity        = "session.inactivity"
	SessionInactivityTimeout = "session.inactivity-timeout"
	SessionMaxLifetime       = "session.max-lifetime"
)

func sessionFlags() {
	flag.Bool(SessionForwardAuth, false, "Enable endpoint for forward authentication.")
	flag.Bool(SessionInactivity, false, "Automatically expire user sessions if they have not refreshed their tokens within a given duration.")
	flag.Duration(SessionInactivityTimeout, 30*time.Minute, "Inactivity timeout for user sessions.")
	flag.Duration(SessionMaxLifetime, 10*time.Hour, "Max lifetime for user sessions.")
}
