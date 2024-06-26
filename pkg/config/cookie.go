package config

import (
	"fmt"
	"net/http"
	"slices"

	flag "github.com/spf13/pflag"
)

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
	if slices.Contains(sameSiteAll(), s) {
		return nil
	}
	return fmt.Errorf("%q must be one of %q (was %q)", CookieSameSite, sameSiteAll(), s)
}

func sameSiteAll() []SameSite {
	return []SameSite{
		SameSiteLax,
		SameSiteNone,
		SameSiteStrict,
	}
}

const (
	CookiePrefix   = "cookie-prefix"
	CookieSameSite = "cookie-same-site"
	EncryptionKey  = "encryption-key"
	LegacyCookie   = "legacy-cookie"
)

func cookieFlags() {
	flag.String(CookiePrefix, "io.nais.wonderwall", "Prefix for cookie names.")
	flag.String(CookieSameSite, string(SameSiteLax), "SameSite attribute for session cookies.")
	flag.String(EncryptionKey, "", "Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.")
	flag.Bool(LegacyCookie, false, "Set legacy session cookie.")
}
