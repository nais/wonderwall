package config

import (
	"fmt"
	"time"

	flag "github.com/spf13/pflag"
)

type Session struct {
	ForwardAuth           bool          `json:"forward-auth"`
	ForwardAuthSetHeaders bool          `json:"forward-auth-set-headers"`
	Inactivity            bool          `json:"inactivity"`
	InactivityTimeout     time.Duration `json:"inactivity-timeout"`
	MaxLifetime           time.Duration `json:"max-lifetime"`
}

func (s *Session) Validate() error {
	if s.ForwardAuthSetHeaders && !s.ForwardAuth {
		return fmt.Errorf("%q must be enabled when %q is enabled", SessionForwardAuth, SessionForwardAuthSetHeaders)
	}
	return nil
}

const (
	SessionForwardAuth           = "session.forward-auth"
	SessionForwardAuthSetHeaders = "session.forward-auth-set-headers"
	SessionInactivity            = "session.inactivity"
	SessionInactivityTimeout     = "session.inactivity-timeout"
	SessionMaxLifetime           = "session.max-lifetime"
)

func sessionFlags() {
	flag.Bool(SessionForwardAuth, false, "Enable endpoint for forward authentication.")
	flag.Bool(SessionForwardAuthSetHeaders, false, "Set 'X-Wonderwall-Forward-Auth-Token' header for responses from forward-auth endpoint.")
	flag.Bool(SessionInactivity, false, "Automatically expire user sessions if they have not refreshed their tokens within a given duration.")
	flag.Duration(SessionInactivityTimeout, 30*time.Minute, "Inactivity timeout for user sessions.")
	flag.Duration(SessionMaxLifetime, 10*time.Hour, "Max lifetime for user sessions.")
}
