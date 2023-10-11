package config

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/nais/liberator/pkg/conftools"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/nais/wonderwall/pkg/logging"
)

type Config struct {
	BindAddress              string        `json:"bind-address"`
	LogFormat                string        `json:"log-format"`
	LogLevel                 string        `json:"log-level"`
	MetricsBindAddress       string        `json:"metrics-bind-address"`
	ShutdownGracefulPeriod   time.Duration `json:"shutdown-graceful-period"`
	ShutdownWaitBeforePeriod time.Duration `json:"shutdown-wait-before-period"`

	AutoLogin            bool     `json:"auto-login"`
	AutoLoginIgnorePaths []string `json:"auto-login-ignore-paths"`
	CookiePrefix         string   `json:"cookie-prefix"`
	EncryptionKey        string   `json:"encryption-key"`
	Ingresses            []string `json:"ingress"`
	UpstreamHost         string   `json:"upstream-host"`
	UpstreamIP           string   `json:"upstream-ip"`
	UpstreamPort         int      `json:"upstream-port"`

	OpenID  OpenID  `json:"openid"`
	Redis   Redis   `json:"redis"`
	Session Session `json:"session"`
	SSO     SSO     `json:"sso"`
}

type OpenID struct {
	ACRValues             string   `json:"acr-values"`
	Audiences             []string `json:"audiences"`
	ClientID              string   `json:"client-id"`
	ClientJWK             string   `json:"client-jwk"`
	PostLogoutRedirectURI string   `json:"post-logout-redirect-uri"`
	Provider              Provider `json:"provider"`
	ResourceIndicator     string   `json:"resource-indicator"`
	Scopes                []string `json:"scopes"`
	UILocales             string   `json:"ui-locales"`
	WellKnownURL          string   `json:"well-known-url"`
}

func (in OpenID) TrustedAudiences() map[string]bool {
	m := make(map[string]bool)
	m[in.ClientID] = true
	for _, aud := range in.Audiences {
		m[aud] = true
	}

	return m
}

type Redis struct {
	Address               string `json:"address"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	TLS                   bool   `json:"tls"`
	URI                   string `json:"uri"`
	ConnectionIdleTimeout int    `json:"connection-idle-timeout"`
}

func (r *Redis) Client() (*redis.Client, error) {
	opts := &redis.Options{
		Network:  "tcp",
		Addr:     r.Address,
		Username: r.Username,
		Password: r.Password,
	}

	if r.TLS {
		opts.TLSConfig = &tls.Config{}
	}

	if r.URI != "" {
		var err error

		opts, err = redis.ParseURL(r.URI)
		if err != nil {
			return nil, err
		}
	}

	opts.MinIdleConns = 1
	opts.MaxRetries = 5

	if r.ConnectionIdleTimeout > 0 {
		opts.ConnMaxIdleTime = time.Duration(r.ConnectionIdleTimeout) * time.Second
	} else if r.ConnectionIdleTimeout == -1 {
		opts.ConnMaxIdleTime = -1
	}

	return redis.NewClient(opts), nil
}

type Session struct {
	Inactivity        bool          `json:"inactivity"`
	InactivityTimeout time.Duration `json:"inactivity-timeout"`
	MaxLifetime       time.Duration `json:"max-lifetime"`
	Refresh           bool          `json:"refresh"`
	RefreshAuto       bool          `json:"refresh-auto"`
}

type SSO struct {
	Enabled                  bool    `json:"enabled"`
	Domain                   string  `json:"domain"`
	Mode                     SSOMode `json:"mode"`
	SessionCookieName        string  `json:"session-cookie-name"`
	ServerURL                string  `json:"server-url"`
	ServerDefaultRedirectURL string  `json:"server-default-redirect-url"`
}

func (in SSO) IsServer() bool {
	return in.Enabled && in.Mode == SSOModeServer
}

type Provider string

const (
	ProviderAzure    Provider = "azure"
	ProviderIDPorten Provider = "idporten"
	ProviderOpenID   Provider = "openid"
)

type SSOMode string

const (
	SSOModeServer SSOMode = "server"
	SSOModeProxy  SSOMode = "proxy"
)

const (
	BindAddress              = "bind-address"
	LogFormat                = "log-format"
	LogLevel                 = "log-level"
	MetricsBindAddress       = "metrics-bind-address"
	ShutdownGracefulPeriod   = "shutdown-graceful-period"
	ShutdownWaitBeforePeriod = "shutdown-wait-before-period"

	AutoLogin            = "auto-login"
	AutoLoginIgnorePaths = "auto-login-ignore-paths"
	CookiePrefix         = "cookie-prefix"
	EncryptionKey        = "encryption-key"
	Ingress              = "ingress"
	UpstreamHost         = "upstream-host"
	UpstreamIP           = "upstream-ip"
	UpstreamPort         = "upstream-port"

	OpenIDACRValues             = "openid.acr-values"
	OpenIDAudiences             = "openid.audiences"
	OpenIDClientID              = "openid.client-id"
	OpenIDClientJWK             = "openid.client-jwk"
	OpenIDPostLogoutRedirectURI = "openid.post-logout-redirect-uri"
	OpenIDProvider              = "openid.provider"
	OpenIDResourceIndicator     = "openid.resource-indicator"
	OpenIDScopes                = "openid.scopes"
	OpenIDUILocales             = "openid.ui-locales"
	OpenIDWellKnownURL          = "openid.well-known-url"

	RedisAddress               = "redis.address"
	RedisPassword              = "redis.password"
	RedisTLS                   = "redis.tls"
	RedisUsername              = "redis.username"
	RedisURI                   = "redis.uri"
	RedisConnectionIdleTimeout = "redis.connection-idle-timeout"

	SessionInactivity        = "session.inactivity"
	SessionInactivityTimeout = "session.inactivity-timeout"
	SessionMaxLifetime       = "session.max-lifetime"
	SessionRefresh           = "session.refresh"
	SessionRefreshAuto       = "session.refresh-auto"

	SSOEnabled                  = "sso.enabled"
	SSODomain                   = "sso.domain"
	SSOModeFlag                 = "sso.mode"
	SSOServerDefaultRedirectURL = "sso.server-default-redirect-url"
	SSOSessionCookieName        = "sso.session-cookie-name"
	SSOServerURL                = "sso.server-url"
)

func Initialize() (*Config, error) {
	conftools.Initialize("wonderwall")

	flag.String(BindAddress, "127.0.0.1:3000", "Listen address for public connections.")
	flag.String(LogFormat, "json", "Log format, either 'json' or 'text'.")
	flag.String(LogLevel, "info", "Logging verbosity level.")
	flag.String(MetricsBindAddress, "127.0.0.1:3001", "Listen address for metrics only.")
	flag.Duration(ShutdownGracefulPeriod, 30*time.Second, "Graceful shutdown period when receiving a shutdown signal after which the server is forcibly exited.")
	flag.Duration(ShutdownWaitBeforePeriod, 0*time.Second, "Wait period when receiving a shutdown signal before actually starting a graceful shutdown. Useful for allowing propagation of Endpoint updates in Kubernetes.")

	flag.Bool(AutoLogin, false, "Enforce authentication if the user does not have a valid session for all matching upstream paths. Automatically redirects HTTP navigation requests to login, otherwise responds with 401 with the Location header set.")
	flag.StringSlice(AutoLoginIgnorePaths, []string{}, "Comma separated list of absolute paths to ignore when 'auto-login' is enabled. Supports basic wildcard matching with glob-style asterisks. Invalid patterns are ignored.")
	flag.String(CookiePrefix, "io.nais.wonderwall", "Prefix for cookie names.")
	flag.String(EncryptionKey, "", "Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.")
	flag.StringSlice(Ingress, []string{}, "Comma separated list of ingresses used to access the main application.")
	flag.String(UpstreamHost, "127.0.0.1:8080", "Address of upstream host.")
	flag.String(UpstreamIP, "", "IP of upstream host. Overrides 'upstream-host' if set.")
	flag.Int(UpstreamPort, 0, "Port of upstream host. Overrides 'upstream-host' if set.")

	flag.String(OpenIDACRValues, "", "Space separated string that configures the default security level (acr_values) parameter for authorization requests.")
	flag.StringSlice(OpenIDAudiences, []string{}, "List of additional trusted audiences (other than the client_id) for OpenID Connect id_token validation.")
	flag.String(OpenIDClientID, "", "Client ID for the OpenID client.")
	flag.String(OpenIDClientJWK, "", "JWK containing the private key for the OpenID client in string format.")
	flag.String(OpenIDPostLogoutRedirectURI, "", "URI for redirecting the user after successful logout at the Identity Provider.")
	flag.String(OpenIDProvider, string(ProviderOpenID), "Provider configuration to load and use, either 'openid', 'azure', 'idporten'.")
	flag.String(OpenIDResourceIndicator, "", "OAuth2 resource indicator to include in authorization request for acquiring audience-restricted tokens.")
	flag.StringSlice(OpenIDScopes, []string{}, "List of additional scopes (other than 'openid') that should be used during the login flow.")
	flag.String(OpenIDUILocales, "", "Space-separated string that configures the default UI locale (ui_locales) parameter for OAuth2 consent screen.")
	flag.String(OpenIDWellKnownURL, "", "URI to the well-known OpenID Configuration metadata document.")

	flag.String(RedisURI, "", "Redis URI string. Prefer using this. An empty value will fall back to 'redis-address'.")
	flag.String(RedisAddress, "", "Address of the Redis instance (host:port). An empty value will use in-memory session storage. Does not override address set by 'redis.uri'.")
	flag.String(RedisPassword, "", "Password for Redis. Does not override password set by 'redis.uri'.")
	flag.Bool(RedisTLS, true, "Whether or not to use TLS for connecting to Redis. Does not override TLS config set by 'redis.uri'.")
	flag.String(RedisUsername, "", "Username for Redis. Does not override username set by 'redis.uri'.")
	flag.Int(RedisConnectionIdleTimeout, 0, "Idle timeout for Redis connections, in seconds. If non-zero, the value should be less than the client timeout configured at the Redis server. A value of -1 disables timeout. If zero, the default value from go-redis is used (30 minutes). Overrides options set by 'redis.uri'.")

	flag.Bool(SessionInactivity, false, "Automatically expire user sessions if they have not refreshed their tokens within a given duration.")
	flag.Duration(SessionInactivityTimeout, 30*time.Minute, "Inactivity timeout for user sessions.")
	flag.Duration(SessionMaxLifetime, 10*time.Hour, "Max lifetime for user sessions.")
	flag.Bool(SessionRefresh, true, "Enable refresh tokens.")
	flag.Bool(SessionRefreshAuto, true, "Enable automatic refresh of tokens. Only available in standalone mode. Will automatically refresh tokens if they are expired as long as the session is valid (i.e. not exceeding 'session.max-lifetime' or 'session.inactivity-timeout').")

	flag.Bool(SSOEnabled, false, "Enable single sign-on mode; one server acting as the OIDC Relying Party, and N proxies. The proxies delegate most endpoint operations to the server, and only implements a reverse proxy that reads the user's session data from the shared store.")
	flag.String(SSODomain, "", "The domain that the session cookies should be set for, usually the second-level domain name (e.g. example.com).")
	flag.String(SSOModeFlag, string(SSOModeServer), "The SSO mode for this instance. Must be one of 'server' or 'proxy'.")
	flag.String(SSOSessionCookieName, "", "Session cookie name. Must be the same across all SSO Servers and Proxies.")
	flag.String(SSOServerDefaultRedirectURL, "", "The URL that the SSO server should redirect to by default if a given redirect query parameter is invalid.")
	flag.String(SSOServerURL, "", "The URL used by the proxy to point to the SSO server instance.")

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
		viper.BindEnv(OpenIDClientID, "IDPORTEN_CLIENT_ID")
		viper.BindEnv(OpenIDClientJWK, "IDPORTEN_CLIENT_JWK")
		viper.BindEnv(OpenIDWellKnownURL, "IDPORTEN_WELL_KNOWN_URL")

		viper.SetDefault(OpenIDACRValues, acr.IDPortenLevel4) // TODO - change to new value after migration
		viper.SetDefault(OpenIDUILocales, "nb")
	case ProviderAzure:
		viper.BindEnv(OpenIDClientID, "AZURE_APP_CLIENT_ID")
		viper.BindEnv(OpenIDClientJWK, "AZURE_APP_JWK")
		viper.BindEnv(OpenIDWellKnownURL, "AZURE_APP_WELL_KNOWN_URL")
	default:
		viper.Set(OpenIDProvider, ProviderOpenID)
	}

	cfg := new(Config)
	err := viper.UnmarshalExact(cfg, func(dc *mapstructure.DecoderConfig) {
		dc.TagName = "json"
	})
	if err != nil {
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

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	cfg.upstreamHostOverride()

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Session.Inactivity && !c.Session.Refresh {
		return fmt.Errorf("%q cannot be enabled without %q", SessionInactivity, SessionRefresh)
	}

	if c.Session.RefreshAuto && !c.Session.Refresh {
		return fmt.Errorf("%q cannot be enabled without %q", SessionRefreshAuto, SessionRefresh)
	}

	if c.SSO.Enabled {
		if len(c.Redis.Address) == 0 && len(c.Redis.URI) == 0 {
			return fmt.Errorf("at least one of %q or %q must be set when %s is set", RedisAddress, RedisURI, SSOEnabled)
		}

		if len(c.SSO.SessionCookieName) == 0 {
			return fmt.Errorf("%q must not be empty when %s is set", SSOSessionCookieName, SSOEnabled)
		}

		if c.Session.RefreshAuto {
			return fmt.Errorf("%q cannot be enabled when %q is enabled", SessionRefreshAuto, SSOEnabled)
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

	if c.upstreamPortSet() {
		if !c.upstreamIpSet() {
			return fmt.Errorf("%q must be set when %q is set (was '%d')", UpstreamIP, UpstreamPort, c.UpstreamPort)
		}
		if !c.upstreamPortValid() {
			return fmt.Errorf("%q must be in valid range (between '1' and '65535', was '%d')", UpstreamPort, c.UpstreamPort)
		}
	}

	if c.upstreamIpSet() && !c.upstreamPortSet() {
		return fmt.Errorf("%q must be set when %q is set (was %q)", UpstreamPort, UpstreamIP, c.UpstreamIP)
	}

	if c.ShutdownGracefulPeriod <= c.ShutdownWaitBeforePeriod {
		return fmt.Errorf("%q must be greater than %q", ShutdownGracefulPeriod, ShutdownWaitBeforePeriod)
	}

	return nil
}

func (c *Config) upstreamIpSet() bool {
	return c.UpstreamIP != ""
}

func (c *Config) upstreamPortSet() bool {
	return c.UpstreamPort != 0
}

func (c *Config) upstreamPortValid() bool {
	return c.UpstreamPort >= 1 && c.UpstreamPort <= 65535
}

func (c *Config) upstreamHostOverride() {
	if c.upstreamIpSet() && c.upstreamPortSet() && c.upstreamPortValid() {
		override := fmt.Sprintf("%s:%d", c.UpstreamIP, c.UpstreamPort)

		log.WithField("logger", "wonderwall.config").
			Infof("%q and %q were set; overriding %q from %q to %q", UpstreamHost, UpstreamPort, UpstreamHost, c.UpstreamHost, override)

		c.UpstreamHost = override
	}
}
