package config

import (
	"time"

	"github.com/nais/liberator/pkg/conftools"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	BindAddress        string `json:"bind-address"`
	LogFormat          string `json:"log-format"`
	LogLevel           string `json:"log-level"`
	MetricsBindAddress string `json:"metrics-bind-address"`

	AutoLogin          bool          `json:"auto-login"`
	EncryptionKey      string        `json:"encryption-key"`
	ErrorRedirectURI   string        `json:"error-redirect-uri"`
	Ingress            string        `json:"ingress"`
	RefreshToken       bool          `json:"refresh-token"`
	SessionMaxLifetime time.Duration `json:"session-max-lifetime"`
	UpstreamHost       string        `json:"upstream-host"`

	OpenID OpenID `json:"openid"`
	Redis  Redis  `json:"redis"`
}

const (
	BindAddress        = "bind-address"
	LogFormat          = "log-format"
	LogLevel           = "log-level"
	MetricsBindAddress = "metrics-bind-address"

	AutoLogin          = "auto-login"
	EncryptionKey      = "encryption-key"
	ErrorRedirectURI   = "error-redirect-uri"
	Ingress            = "ingress"
	SessionMaxLifetime = "session-max-lifetime"
	RefreshToken       = "refresh-token"
	UpstreamHost       = "upstream-host"
)

func Initialize() (*Config, error) {
	conftools.Initialize("wonderwall")

	flag.String(BindAddress, "127.0.0.1:3000", "Listen address for public connections.")
	flag.String(LogFormat, "json", "Log format, either 'json' or 'text'.")
	flag.String(LogLevel, "debug", "Logging verbosity level.")
	flag.String(MetricsBindAddress, "127.0.0.1:3001", "Listen address for metrics only.")

	flag.Bool(AutoLogin, false, "Automatically redirect user to login if the user does not have a valid session for all proxied downstream requests.")
	flag.String(EncryptionKey, "", "Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.")
	flag.String(ErrorRedirectURI, "", "URI to redirect user to on errors for custom error handling.")
	flag.String(Ingress, "", "Ingress used to access the main application.")
	flag.Bool(RefreshToken, false, "Refresh token enabled.")
	flag.Duration(SessionMaxLifetime, time.Hour, "Max lifetime for user sessions.")
	flag.String(UpstreamHost, "127.0.0.1:8080", "Address of upstream host.")

	redisFlags()
	openIDFlags()

	flag.String(OpenIDProvider, string(ProviderOpenID), "Provider configuration to load and use, either 'openid', 'azure', 'idporten'.")
	flag.Parse()

	if err := viper.ReadInConfig(); err != nil {
		if err.(viper.ConfigFileNotFoundError) != err {
			return nil, err
		}
	}
	if err := viper.BindPFlags(flag.CommandLine); err != nil {
		return nil, err
	}

	switch Provider(viper.GetString(OpenIDProvider)) {
	case ProviderIDPorten:
		idportenFlags()
	case ProviderAzure:
		azureFlags()
	default:
		viper.Set(OpenIDProvider, ProviderOpenID)
	}

	return &Config{}, nil
}
