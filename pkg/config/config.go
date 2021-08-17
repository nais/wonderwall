package config

import (
	flag "github.com/spf13/pflag"

	"github.com/nais/liberator/pkg/conftools"
	"github.com/spf13/viper"
)

type Config struct {
	IDPorten  IDPorten `json:"idporten"`
	LogFormat string   `json:"log-format"`
	LogLevel  string   `json:"log-level"`
}

type IDPorten struct {
	ClientID     string `json:"client-id"`
	ClientJWK    string `json:"client-jwk"`
	RedirectURI  string `json:"redirect-uri"`
	WellKnownURL string `json:"well-known-url"`
}

const (
	LogFormat            = "log-format"
	LogLevel             = "log-level"
	IDPortenClientID     = "idporten.client-id"
	IDPortenClientJWK    = "idporten.client-jwk"
	IDPortenRedirectURI  = "idporten.redirect-uri"
	IDPortenWellKnownURL = "idporten.well-known-url"
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

	return &Config{}
}
