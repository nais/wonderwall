package config

import (
	"fmt"
	"time"

	flag "github.com/spf13/pflag"
)

type Session struct {
	Inactivity        bool          `json:"inactivity"`
	InactivityTimeout time.Duration `json:"inactivity-timeout"`
	MaxLifetime       time.Duration `json:"max-lifetime"`
	Refresh           bool          `json:"refresh"`
	RefreshAuto       bool          `json:"refresh-auto"`
}

func (s Session) Validate() error {
	if s.Inactivity && !s.Refresh {
		return fmt.Errorf("%q cannot be enabled without %q", SessionInactivity, SessionRefresh)
	}

	if s.RefreshAuto && !s.Refresh {
		return fmt.Errorf("%q cannot be enabled without %q", SessionRefreshAuto, SessionRefresh)
	}

	return nil
}

const (
	SessionInactivity        = "session.inactivity"
	SessionInactivityTimeout = "session.inactivity-timeout"
	SessionMaxLifetime       = "session.max-lifetime"
	SessionRefresh           = "session.refresh"
	SessionRefreshAuto       = "session.refresh-auto"
)

func sessionFlags() {
	flag.Bool(SessionInactivity, false, "Automatically expire user sessions if they have not refreshed their tokens within a given duration.")
	flag.Duration(SessionInactivityTimeout, 30*time.Minute, "Inactivity timeout for user sessions.")
	flag.Duration(SessionMaxLifetime, 10*time.Hour, "Max lifetime for user sessions.")
	flag.Bool(SessionRefresh, true, "Enable refresh tokens.")
	flag.Bool(SessionRefreshAuto, true, "Enable automatic refresh of tokens. Only available in standalone mode. Will automatically refresh tokens if they are expired as long as the session is valid (i.e. not exceeding 'session.max-lifetime' or 'session.inactivity-timeout').")
}
