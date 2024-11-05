package config

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	flag "github.com/spf13/pflag"
)

type Cookie struct {
	Prefix   string   `json:"prefix"`
	SameSite SameSite `json:"same-site"`
	Secure   bool     `json:"secure"`
}

func (c *Cookie) Validate(cfg *Config) error {
	if err := c.SameSite.Validate(); err != nil {
		return err
	}

	if c.Secure {
		return nil
	}

	for _, ingress := range cfg.Ingresses {
		u, err := url.ParseRequestURI(ingress)
		if err != nil {
			return fmt.Errorf("parsing ingress URL %q: %w", ingress, err)
		}

		if !strings.EqualFold(u.Hostname(), "localhost") {
			return fmt.Errorf("ingress %q is not localhost (was %q); cannot disable secure cookies", ingress, u.Hostname())
		}

		if u.Scheme != "http" {
			return fmt.Errorf("ingress %q is not HTTP (was %q); cannot disable secure cookies", ingress, u.Scheme)
		}
	}

	logger.Warn("secure cookies are disabled; not suitable for production use!")
	return nil
}

type SameSite string

const (
	SameSiteLax    SameSite = "Lax"
	SameSiteNone   SameSite = "None"
	SameSiteStrict SameSite = "Strict"
)

// ToHttp returns the equivalent http.SameSite value for the SameSite attribute.
func (s SameSite) ToHttp() http.SameSite {
	switch s {
	case SameSiteNone:
		return http.SameSiteNoneMode
	case SameSiteStrict:
		return http.SameSiteStrictMode
	default:
		return http.SameSiteLaxMode
	}
}

func (s SameSite) Validate() error {
	all := []SameSite{
		SameSiteLax,
		SameSiteNone,
		SameSiteStrict,
	}

	if slices.Contains(all, s) {
		return nil
	}
	return fmt.Errorf("%q must be one of %q (was %q)", CookieSameSite, all, s)
}

const (
	CookiePrefix   = "cookie.prefix"
	CookieSameSite = "cookie.same-site"
	CookieSecure   = "cookie.secure"
	EncryptionKey  = "encryption-key"
	LegacyCookie   = "legacy-cookie"
)

func cookieFlags() {
	flag.String(CookiePrefix, "io.nais.wonderwall", "Prefix for cookie names.")
	flag.String(CookieSameSite, string(SameSiteLax), "SameSite attribute for session cookies.")
	flag.Bool(CookieSecure, true, "Set secure flag on session cookies. Can only be disabled when `ingress` only consist of localhost hosts. Generally, disabling this is only necessary when using Safari.")
	flag.String(EncryptionKey, "", "Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.")
	flag.Bool(LegacyCookie, false, "Set legacy session cookie.")
}
