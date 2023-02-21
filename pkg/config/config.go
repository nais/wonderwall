package config

import (
	"fmt"
	"net/url"
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
	Ingresses            []string `json:"ingress"`
	Session              Session  `json:"session"`
	UpstreamHost         string   `json:"upstream-host"`

	OpenID OpenID `json:"openid"`
	Redis  Redis  `json:"redis"`

	SSO SSO `json:"sso"`
}

type Session struct {
	Inactivity        bool          `json:"inactivity"`
	InactivityTimeout time.Duration `json:"inactivity-timeout"`
	MaxLifetime       time.Duration `json:"max-lifetime"`
	Refresh           bool          `json:"refresh"`
}

type SSO struct {
	Enabled                  bool    `json:"enabled"`
	Domain                   string  `json:"domain"`
	Mode                     SSOMode `json:"mode"`
	ServerURL                string  `json:"server-url"`
	ServerDefaultRedirectURL string  `json:"server-default-redirect-url"`
}

type SSOMode string

const (
	SSOModeServer SSOMode = "server"
	SSOModeProxy  SSOMode = "proxy"
)

const (
	BindAddress        = "bind-address"
	LogFormat          = "log-format"
	LogLevel           = "log-level"
	MetricsBindAddress = "metrics-bind-address"

	AutoLogin            = "auto-login"
	AutoLoginIgnorePaths = "auto-login-ignore-paths"
	EncryptionKey        = "encryption-key"
	Ingress              = "ingress"
	UpstreamHost         = "upstream-host"

	SessionInactivity           = "session.inactivity"
	SessionInactivityTimeout    = "session.inactivity-timeout"
	SessionMaxLifetime          = "session.max-lifetime"
	SessionRefresh              = "session.refresh"
	SSOEnabled                  = "sso.enabled"
	SSODomain                   = "sso.domain"
	SSOServerDefaultRedirectURL = "sso.server-default-redirect-url"
	SSOModeFlag                 = "sso.mode"
	SSOServerURL                = "sso.server-url"
)

func Initialize() (*Config, error) {
	conftools.Initialize("wonderwall")

	flag.String(BindAddress, "127.0.0.1:3000", "Listen address for public connections.")
	flag.String(LogFormat, "json", "Log format, either 'json' or 'text'.")
	flag.String(LogLevel, "info", "Logging verbosity level.")
	flag.String(MetricsBindAddress, "127.0.0.1:3001", "Listen address for metrics only.")

	flag.Bool(AutoLogin, false, "Automatically redirect all HTTP GET requests to login if the user does not have a valid session for all matching upstream paths.")
	flag.StringSlice(AutoLoginIgnorePaths, []string{}, "Comma separated list of absolute paths to ignore when 'auto-login' is enabled. Supports basic wildcard matching with glob-style asterisks. Invalid patterns are ignored.")
	flag.String(EncryptionKey, "", "Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.")
	flag.StringSlice(Ingress, []string{}, "Comma separated list of ingresses used to access the main application.")
	flag.String(UpstreamHost, "127.0.0.1:8080", "Address of upstream host.")

	flag.Bool(SessionInactivity, false, "Automatically expire user sessions if they have not refreshed their tokens within a given duration.")
	flag.Duration(SessionInactivityTimeout, 30*time.Minute, "Inactivity timeout for user sessions.")
	flag.Duration(SessionMaxLifetime, time.Hour, "Max lifetime for user sessions.")
	flag.Bool(SessionRefresh, false, "Automatically refresh the tokens for user sessions if they are expired, as long as the session exists (indicated by the session max lifetime).")

	flag.Bool(SSOEnabled, false, "Enable single sign-on mode; one server acting as the OIDC Relying Party, and N proxies. The proxies delegate most endpoint operations to the server, and only implements a reverse proxy that reads the user's session data from the shared store.")
	flag.String(SSODomain, "", "The domain that the session cookies should be set for, usually the second-level domain name (e.g. example.com).")
	flag.String(SSOModeFlag, string(SSOModeServer), "The SSO mode for this instance. Must be one of 'server' or 'proxy'.")
	flag.String(SSOServerDefaultRedirectURL, "", "The URL that the SSO server should redirect to by default if the a given redirect query parameter is invalid.")
	flag.String(SSOServerURL, "", "The URL used by the proxy to point to the SSO server instance.")

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

	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Session.Inactivity && !c.Session.Refresh {
		return fmt.Errorf("%q cannot be enabled without %q", SessionInactivity, SessionRefresh)
	}

	if c.SSO.Enabled {
		if len(c.Redis.Address) == 0 {
			return fmt.Errorf("%q must not be empty when %s is set", RedisAddress, SSOEnabled)
		}

		switch c.SSO.Mode {
		case SSOModeProxy:
			_, err := url.ParseRequestURI(c.SSO.ServerURL)
			if err != nil {
				return fmt.Errorf("%q must be a valid url: %w", SSOServerURL, err)
			}
		case SSOModeServer:
			if len(c.SSO.Domain) == 0 {
				return fmt.Errorf("%q cannot be empty", SSODomain)
			}

			_, err := url.ParseRequestURI(c.SSO.ServerDefaultRedirectURL)
			if err != nil {
				return fmt.Errorf("%q must be a valid url: %w", SSOServerDefaultRedirectURL, err)
			}
		default:
			return fmt.Errorf("%q must be one of [%q, %q]", SSOModeFlag, SSOModeServer, SSOModeProxy)
		}
	}

	return nil
}
