package config

import (
	"fmt"
	"net/url"

	flag "github.com/spf13/pflag"
)

type SSOMode string

const (
	SSOModeServer SSOMode = "server"
	SSOModeProxy  SSOMode = "proxy"
)

type SSO struct {
	Enabled                  bool    `json:"enabled"`
	Domain                   string  `json:"domain"`
	Mode                     SSOMode `json:"mode"`
	SessionCookieName        string  `json:"session-cookie-name"`
	ServerURL                string  `json:"server-url"`
	ServerDefaultRedirectURL string  `json:"server-default-redirect-url"`
}

func (s SSO) IsServer() bool {
	return s.Enabled && s.Mode == SSOModeServer
}

func (s SSO) Validate(c *Config) error {
	if !s.Enabled {
		return nil
	}

	if len(c.Redis.Address) == 0 && len(c.Redis.URI) == 0 {
		return fmt.Errorf("at least one of %q or %q must be set when %s is set", RedisAddress, RedisURI, SSOEnabled)
	}

	if c.Session.RefreshAuto {
		return fmt.Errorf("%q cannot be enabled when %q is enabled", SessionRefreshAuto, SSOEnabled)
	}

	if len(s.SessionCookieName) == 0 {
		return fmt.Errorf("%q must not be empty when %s is set", SSOSessionCookieName, SSOEnabled)
	}

	switch s.Mode {
	case SSOModeProxy:
		_, err := url.ParseRequestURI(s.ServerURL)
		if err != nil {
			return fmt.Errorf("%q must be a valid url: %w", SSOServerURL, err)
		}
	case SSOModeServer:
		if len(s.Domain) == 0 {
			return fmt.Errorf("%q cannot be empty", SSODomain)
		}

		_, err := url.ParseRequestURI(s.ServerDefaultRedirectURL)
		if err != nil {
			return fmt.Errorf("%q must be a valid url: %w", SSOServerDefaultRedirectURL, err)
		}
	default:
		return fmt.Errorf("%q must be one of [%q, %q]", SSOModeFlag, SSOModeServer, SSOModeProxy)
	}

	return nil
}

const (
	SSOEnabled                  = "sso.enabled"
	SSODomain                   = "sso.domain"
	SSOModeFlag                 = "sso.mode"
	SSOServerDefaultRedirectURL = "sso.server-default-redirect-url"
	SSOSessionCookieName        = "sso.session-cookie-name"
	SSOServerURL                = "sso.server-url"
)

func ssoFlags() {
	flag.Bool(SSOEnabled, false, "Enable single sign-on mode; one server acting as the OIDC Relying Party, and N proxies. The proxies delegate most endpoint operations to the server, and only implements a reverse proxy that reads the user's session data from the shared store.")
	flag.String(SSODomain, "", "The domain that the session cookies should be set for, usually the second-level domain name (e.g. example.com).")
	flag.String(SSOModeFlag, string(SSOModeServer), "The SSO mode for this instance. Must be one of 'server' or 'proxy'.")
	flag.String(SSOSessionCookieName, "", "Session cookie name. Must be the same across all SSO Servers and Proxies.")
	flag.String(SSOServerDefaultRedirectURL, "", "The URL that the SSO server should redirect to by default if a given redirect query parameter is invalid.")
	flag.String(SSOServerURL, "", "The URL used by the proxy to point to the SSO server instance.")
}
