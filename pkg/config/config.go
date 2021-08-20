package config

import (
	flag "github.com/spf13/pflag"

	"github.com/nais/liberator/pkg/conftools"
	"github.com/spf13/viper"
)

type Config struct {
	BindAddress  string   `json:"bind-address"`
	UpstreamHost string   `json:"upstream-host"`
	IDPorten     IDPorten `json:"idporten"`
	LogFormat    string   `json:"log-format"`
	LogLevel     string   `json:"log-level"`
}

type IDPorten struct {
	ClientID      string            `json:"client-id"`
	ClientJWK     string            `json:"client-jwk"`
	RedirectURI   string            `json:"redirect-uri"`
	WellKnownURL  string            `json:"well-known-url"`
	WellKnown     IDPortenWellKnown `json:"well-known"`
	Locale        string            `json:"locale"`
	SecurityLevel string            `json:"security-level"`
}

const (
	BindAddress           = "bind-address"
	UpstreamHost          = "upstream-host"
	LogFormat             = "log-format"
	LogLevel              = "log-level"
	IDPortenClientID      = "idporten.client-id"
	IDPortenClientJWK     = "idporten.client-jwk"
	IDPortenRedirectURI   = "idporten.redirect-uri"
	IDPortenWellKnownURL  = "idporten.well-known-url"
	IDPortenLocale        = "idporten.locale"
	IDPortenSecurityLevel = "idporten.security-level"
)

func bindNAIS() {
	viper.BindEnv(IDPortenClientID, "IDPORTEN_CLIENT_ID")
	viper.BindEnv(IDPortenClientJWK, "IDPORTEN_CLIENT_JWK")
	viper.BindEnv(IDPortenRedirectURI, "IDPORTEN_REDIRECT_URI")
	viper.BindEnv(IDPortenWellKnownURL, "IDPORTEN_WELL_KNOWN_URL")
}

func Initialize() *Config {
	conftools.Initialize("wonderwall")
	bindNAIS()

	flag.String(LogFormat, "text", "Log format, either 'json' or 'text'.")
	flag.String(LogLevel, "debug", "Logging verbosity level.")
	flag.String(BindAddress, "127.0.0.1:8090", "Listen address.")
	flag.String(UpstreamHost, "127.0.0.1:8080", "Address of upstream host.")
	flag.String(IDPortenSecurityLevel, "Level4", "Requested security level, either Level3 or Level4.")
	flag.String(IDPortenLocale, "nb", "Locale for OAuth2 consent screen.")

	return &Config{}
}
