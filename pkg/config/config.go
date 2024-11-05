package config

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/nais/liberator/pkg/conftools"
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
	Version                  string        `json:"version"`

	AutoLogin            bool     `json:"auto-login"`
	AutoLoginIgnorePaths []string `json:"auto-login-ignore-paths"`
	Cookie               Cookie   `json:"cookie"`
	CookiePrefix         string   `json:"cookie-prefix"`
	CookieSameSite       SameSite `json:"cookie-same-site"`
	EncryptionKey        string   `json:"encryption-key"`
	Ingresses            []string `json:"ingress"`
	LegacyCookie         bool     `json:"legacy-cookie"`
	UpstreamAccessLogs   bool     `json:"upstream-access-logs"`
	UpstreamHost         string   `json:"upstream-host"`
	UpstreamIP           string   `json:"upstream-ip"`
	UpstreamPort         int      `json:"upstream-port"`

	OpenTelemetry OpenTelemetry `json:"otel"`
	OpenID        OpenID        `json:"openid"`
	Redis         Redis         `json:"redis"`
	Session       Session       `json:"session"`
	SSO           SSO           `json:"sso"`
}

const (
	BindAddress              = "bind-address"
	LogFormat                = "log-format"
	LogLevel                 = "log-level"
	MetricsBindAddress       = "metrics-bind-address"
	ShutdownGracefulPeriod   = "shutdown-graceful-period"
	ShutdownWaitBeforePeriod = "shutdown-wait-before-period"

	AutoLogin            = "auto-login"
	AutoLoginIgnorePaths = "auto-login-ignore-paths"
	Ingress              = "ingress"
	UpstreamAccessLogs   = "upstream-access-logs"
	UpstreamHost         = "upstream-host"
	UpstreamIP           = "upstream-ip"
	UpstreamPort         = "upstream-port"
)

var logger = log.WithField("logger", "wonderwall.config")

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
	flag.StringSlice(Ingress, []string{}, "Comma separated list of ingresses used to access the main application.")
	flag.Bool(UpstreamAccessLogs, false, "Enable access logs for upstream requests.")
	flag.String(UpstreamHost, "127.0.0.1:8080", "Address of upstream host.")
	flag.String(UpstreamIP, "", "IP of upstream host. Overrides 'upstream-host' if set.")
	flag.Int(UpstreamPort, 0, "Port of upstream host. Overrides 'upstream-host' if set.")

	cookieFlags()
	openidFlags()
	otelFlags()
	redisFlags()
	sessionFlags()
	ssoFlags()

	flag.Parse()

	if err := viper.ReadInConfig(); err != nil {
		if !errors.Is(err, err.(viper.ConfigFileNotFoundError)) {
			return nil, err
		}
	}
	if err := viper.BindPFlags(flag.CommandLine); err != nil {
		return nil, err
	}

	level := viper.GetString(LogLevel)
	format := viper.GetString(LogFormat)
	if err := logging.Setup(level, format); err != nil {
		return nil, err
	}

	resolveOpenIdProvider()
	resolveUpstream()
	resolveVersion()

	cfg := new(Config)
	if err := viper.UnmarshalExact(cfg, func(dc *mapstructure.DecoderConfig) {
		dc.TagName = "json"
	}); err != nil {
		return nil, err
	}

	const redacted = "**REDACTED**"
	masked := *cfg
	masked.EncryptionKey = redacted
	masked.OpenID.ClientJWK = redacted
	masked.OpenID.ClientSecret = redacted
	masked.Redis.Password = redacted
	logger.Infof("config: %+v", masked)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if err := c.Cookie.Validate(c); err != nil {
		return err
	}

	// TODO: move this into Cookie
	if err := c.CookieSameSite.Validate(); err != nil {
		return err
	}

	if err := c.OpenID.Validate(); err != nil {
		return err
	}

	if err := c.Session.Validate(); err != nil {
		return err
	}

	if err := c.SSO.Validate(c); err != nil {
		return err
	}

	if err := c.validateUpstream(); err != nil {
		return err
	}

	if c.ShutdownGracefulPeriod <= c.ShutdownWaitBeforePeriod {
		return fmt.Errorf("%q must be greater than %q", ShutdownGracefulPeriod, ShutdownWaitBeforePeriod)
	}

	return nil
}

func (c *Config) validateUpstream() error {
	if c.UpstreamIP == "" && c.UpstreamPort == 0 {
		return nil
	}

	if c.UpstreamIP == "" {
		return fmt.Errorf("%q must be set when %q is set", UpstreamIP, UpstreamPort)
	}

	if c.UpstreamPort == 0 {
		return fmt.Errorf("%q must be set when %q is set", UpstreamPort, UpstreamIP)
	}

	if c.UpstreamPort < 1 || c.UpstreamPort > 65535 {
		return fmt.Errorf("%q must be in valid range (between '1' and '65535', was '%d')", UpstreamPort, c.UpstreamPort)
	}

	return nil
}

func resolveUpstream() {
	ip := viper.GetString(UpstreamIP)
	port := viper.GetInt(UpstreamPort)
	host := viper.GetString(UpstreamHost)

	if ip != "" && port > 0 {
		resolved := fmt.Sprintf("%s:%d", ip, port)
		logger.Debugf("%q and %q were set; overriding %q from %q to %q", UpstreamHost, UpstreamPort, UpstreamHost, host, resolved)

		viper.Set(UpstreamHost, resolved)
	}
}

func resolveVersion() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	var rev string
	var last time.Time

	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			rev = kv.Value
		case "vcs.time":
			last, _ = time.Parse(time.RFC3339, kv.Value)
		}
	}

	if len(rev) > 7 {
		rev = rev[:7]
	}

	viper.Set("version", fmt.Sprintf("%s-%s", last.Format("2006-01-02-150405"), rev))
}
