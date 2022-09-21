package config

import (
	"time"

	"github.com/nais/liberator/pkg/conftools"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/nais/wonderwall/pkg/logging"
)

type Config struct {
	BindAddress        string `json:"bind-address"`
	LogFormat          string `json:"log-format"`
	LogLevel           string `json:"log-level"`
	MetricsBindAddress string `json:"metrics-bind-address"`

	AutoLogin            bool     `json:"auto-login"`
	AutoLoginIgnorePaths []string `json:"auto-login-ignore-paths"`
	EncryptionKey        string   `json:"encryption-key"`
	ErrorPath            string   `json:"error-path"`
	Ingresses            []string `json:"ingress"`
	Session              Session  `json:"session"`
	UpstreamHost         string   `json:"upstream-host"`

	OpenID OpenID `json:"openid"`
	Redis  Redis  `json:"redis"`

	Loginstatus Loginstatus `json:"loginstatus"`
}

type Loginstatus struct {
	Enabled           bool   `json:"enabled"`
	CookieDomain      string `json:"cookie-domain"`
	CookieName        string `json:"cookie-name"`
	ResourceIndicator string `json:"resource-indicator"`
	TokenURL          string `json:"token-url"`
}

type Session struct {
	MaxLifetime     time.Duration `json:"max-lifetime"`
	Refresh         bool          `json:"refresh"`
	MetadataRollout bool          `json:"metadata-rollout"`
}

const (
	BindAddress        = "bind-address"
	LogFormat          = "log-format"
	LogLevel           = "log-level"
	MetricsBindAddress = "metrics-bind-address"

	AutoLogin            = "auto-login"
	AutoLoginIgnorePaths = "auto-login-ignore-paths"
	EncryptionKey        = "encryption-key"
	ErrorPath            = "error-path"
	Ingress              = "ingress"
	UpstreamHost         = "upstream-host"

	SessionMaxLifetime     = "session.max-lifetime"
	SessionRefresh         = "session.refresh"
	SessionMetadataRollout = "session.metadata-rollout"

	LoginstatusEnabled           = "loginstatus.enabled"
	LoginstatusCookieDomain      = "loginstatus.cookie-domain"
	LoginstatusCookieName        = "loginstatus.cookie-name"
	LoginstatusResourceIndicator = "loginstatus.resource-indicator"
	LoginstatusTokenURL          = "loginstatus.token-url"
)

func Initialize() (*Config, error) {
	conftools.Initialize("wonderwall")

	flag.String(BindAddress, "127.0.0.1:3000", "Listen address for public connections.")
	flag.String(LogFormat, "json", "Log format, either 'json' or 'text'.")
	flag.String(LogLevel, "info", "Logging verbosity level.")
	flag.String(MetricsBindAddress, "127.0.0.1:3001", "Listen address for metrics only.")

	flag.Bool(AutoLogin, false, "Automatically redirect all HTTP GET requests to login if the user does not have a valid session for all matching upstream paths.")
	flag.StringSlice(AutoLoginIgnorePaths, []string{}, "Comma separated list of absolute paths to ignore when 'auto-login' is enabled. Supports basic wildcard matching with glob-style single asterisks using the stdlib path.Match. Invalid patterns are ignored.")
	flag.String(EncryptionKey, "", "Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.")
	flag.String(ErrorPath, "", "Absolute path to redirect user to on errors for custom error handling.")
	flag.StringSlice(Ingress, []string{}, "Comma separated list of ingresses used to access the main application.")
	flag.String(UpstreamHost, "127.0.0.1:8080", "Address of upstream host.")

	flag.Duration(SessionMaxLifetime, time.Hour, "Max lifetime for user sessions.")
	flag.Bool(SessionRefresh, false, "Automatically refresh the tokens for user sessions if they are expired, as long as the session exists (indicated by the session max lifetime).")
	flag.Bool(SessionMetadataRollout, false, "Feature toggle for metadata rollout.")

	flag.Bool(LoginstatusEnabled, false, "Feature toggle for Loginstatus, a separate service that should provide an opaque token to indicate that a user has been authenticated previously, e.g. by another application in another subdomain.")
	flag.String(LoginstatusCookieDomain, "", "The domain that the cookie should be set for.")
	flag.String(LoginstatusCookieName, "", "The name of the cookie.")
	flag.String(LoginstatusResourceIndicator, "", "The resource indicator that should be included in the authorization request to get an audience-restricted token that Loginstatus accepts. Empty means no resource indicator.")
	flag.String(LoginstatusTokenURL, "", "The URL to the Loginstatus service that returns an opaque token.")

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

	cfg := new(Config)

	if err := conftools.Load(cfg); err != nil {
		return nil, err
	}

	if err := logging.Setup(cfg.LogLevel, cfg.LogFormat); err != nil {
		return nil, err
	}

	log.Tracef("Trace logging enabled")

	maskedConfig := []string{
		OpenIDClientJWK,
		EncryptionKey,
		RedisPassword,
	}

	for _, line := range conftools.Format(maskedConfig) {
		log.WithField("logger", "wonderwall.config").Info(line)
	}

	return cfg, nil
}
