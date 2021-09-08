package config

import (
	"time"

	flag "github.com/spf13/pflag"

	"github.com/nais/liberator/pkg/conftools"
	"github.com/spf13/viper"

	"github.com/nais/wonderwall/pkg/token"
)

type Config struct {
	BindAddress        string   `json:"bind-address"`
	MetricsBindAddress string   `json:"metrics-bind-address"`
	UpstreamHost       string   `json:"upstream-host"`
	EncryptionKey      string   `json:"encryption-key"`
	IDPorten           IDPorten `json:"idporten"`
	LogFormat          string   `json:"log-format"`
	LogLevel           string   `json:"log-level"`
	Redis              string   `json:"redis"`
	Ingresses          []string `json:"ingresses"`
}

type IDPorten struct {
	ClientID              string                `json:"client-id"`
	ClientJWK             string                `json:"client-jwk"`
	RedirectURI           string                `json:"redirect-uri"`
	WellKnownURL          string                `json:"well-known-url"`
	WellKnown             IDPortenWellKnown     `json:"well-known"`
	Locale                IDPortenLocale        `json:"locale"`
	SecurityLevel         IDPortenSecurityLevel `json:"security-level"`
	PostLogoutRedirectURI string                `json:"post-logout-redirect-uri"`
	Scopes                []string              `json:"scopes"`
	SessionMaxLifetime    time.Duration         `json:"session-max-lifetime"`
}

type IDPortenSecurityLevel struct {
	Enabled bool   `json:"enabled"`
	Value   string `json:"value"`
}

type IDPortenLocale struct {
	Enabled bool   `json:"enabled"`
	Value   string `json:"value"`
}

const (
	BindAddress                   = "bind-address"
	MetricsBindAddress            = "metrics-bind-address"
	UpstreamHost                  = "upstream-host"
	LogFormat                     = "log-format"
	LogLevel                      = "log-level"
	EncryptionKey                 = "encryption-key"
	Redis                         = "redis"
	Ingresses                     = "ingresses"
	IDPortenClientID              = "idporten.client-id"
	IDPortenClientJWK             = "idporten.client-jwk"
	IDPortenRedirectURI           = "idporten.redirect-uri"
	IDPortenWellKnownURL          = "idporten.well-known-url"
	IDPortenLocaleEnabled         = "idporten.locale.enabled"
	IDPortenLocaleValue           = "idporten.locale.value"
	IDPortenSecurityLevelEnabled  = "idporten.security-level.enabled"
	IDPortenSecurityLevelValue    = "idporten.security-level.value"
	IDPortenPostLogoutRedirectURI = "idporten.post-logout-redirect-uri"
	IDPortenScopes                = "idporten.scopes"
	IDPortenSessionMaxLifetime    = "idporten.session-max-lifetime"
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
	flag.String(BindAddress, "127.0.0.1:8090", "Listen address for public connections.")
	flag.String(MetricsBindAddress, "127.0.0.1:8091", "Listen address for metrics only.")
	flag.String(UpstreamHost, "127.0.0.1:8080", "Address of upstream host.")
	flag.String(EncryptionKey, "", "Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.")
	flag.String(Redis, "", "Address of Redis. An empty value will use in-memory session storage.")
	flag.Bool(IDPortenSecurityLevelEnabled, true, "Toggle for setting the sceurity level (acr_values) parameter for authorization requests.")
	flag.String(IDPortenSecurityLevelValue, "Level4", "Requested security level, either Level3 or Level4.")
	flag.Bool(IDPortenLocaleEnabled, true, "Toggle for setting the locale parameter for authorization requests.")
	flag.String(IDPortenLocaleValue, "nb", "Locale for OAuth2 consent screen.")
	flag.String(IDPortenPostLogoutRedirectURI, "https://nav.no", "URI for redirecting the user after successful logout at IDPorten.")
	flag.StringSlice(IDPortenScopes, []string{token.ScopeOpenID}, "List of scopes that should be used during the Auth Code flow.")
	flag.Duration(IDPortenSessionMaxLifetime, time.Hour, "Max lifetime for user sessions.")
	flag.StringSlice(Ingresses, []string{"/"}, "Ingresses used to access the main application.")

	return &Config{}
}
