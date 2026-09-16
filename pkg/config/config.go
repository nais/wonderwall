package config

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/nais/liberator/pkg/conftools"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/nais/wonderwall/internal/o11y/logging"
)

type Config struct {
	BindAddress              string        `json:"bind-address"`
	LogFormat                string        `json:"log-format"`
	LogLevel                 string        `json:"log-level"`
	MetricsBindAddress       string        `json:"metrics-bind-address"`
	PprofEnabled             bool          `json:"pprof-enabled"`
	ProbeBindAddress         string        `json:"probe-bind-address"`
	ShutdownGracefulPeriod   time.Duration `json:"shutdown-graceful-period"`
	ShutdownWaitBeforePeriod time.Duration `json:"shutdown-wait-before-period"`
	Version                  string        `json:"version"`

	AutoLogin            bool     `json:"auto-login"`
	AutoLoginIgnorePaths []string `json:"auto-login-ignore-paths"`
	Cookie               Cookie   `json:"cookie"`
	EncryptionKey        string   `json:"encryption-key"`
	Ingresses            []string `json:"ingress"`
	Upstream             Upstream `json:"upstream"`

	OpenTelemetry OpenTelemetry `json:"otel"`
	OpenID        OpenID        `json:"openid"`
	RateLimit     RateLimit     `json:"ratelimit"`
	Redis         Redis         `json:"redis"`
	Session       Session       `json:"session"`
	SSO           SSO           `json:"sso"`
}

const (
	BindAddress              = "bind-address"
	LogFormat                = "log-format"
	LogLevel                 = "log-level"
	MetricsBindAddress       = "metrics-bind-address"
	PprofEnabled             = "pprof-enabled"
	ProbeBindAddress         = "probe-bind-address"
	ShutdownGracefulPeriod   = "shutdown-graceful-period"
	ShutdownWaitBeforePeriod = "shutdown-wait-before-period"

	AutoLogin            = "auto-login"
	AutoLoginIgnorePaths = "auto-login-ignore-paths"
	Ingress              = "ingress"
)

var logger = log.WithField("logger", "wonderwall.config")

func Initialize() (*Config, error) {
	conftools.Initialize("wonderwall")

	flag.String(BindAddress, "127.0.0.1:3000", "Listen address for public connections.")
	flag.String(LogFormat, "json", "Log format, either 'json' or 'text'.")
	flag.String(LogLevel, "info", "Logging verbosity level.")
	flag.String(MetricsBindAddress, "127.0.0.1:3001", "Listen address for metrics only. Empty disables metrics.")
	flag.Bool(PprofEnabled, false, "Enable pprof debug endpoints on the probe server.")
	flag.String(ProbeBindAddress, "", "Listen address for health probe. Empty disables health probe.")
	flag.Duration(ShutdownGracefulPeriod, 30*time.Second, "Graceful shutdown period when receiving a shutdown signal after which the server is forcibly exited.")
	flag.Duration(ShutdownWaitBeforePeriod, 0*time.Second, "Wait period when receiving a shutdown signal before actually starting a graceful shutdown. Useful for allowing propagation of Endpoint updates in Kubernetes.")

	flag.Bool(AutoLogin, false, "Enforce authentication if the user does not have a valid session for all matching upstream paths. Automatically redirects HTTP navigation requests to login, otherwise responds with 401 with the Location header set.")
	flag.StringSlice(AutoLoginIgnorePaths, []string{}, "Comma separated list of absolute paths to ignore when 'auto-login' is enabled. Supports basic wildcard matching with glob-style asterisks. Invalid patterns are ignored.")
	flag.StringSlice(Ingress, []string{}, "Comma separated list of ingresses used to access the main application.")

	// Register canonical and deprecated upstream flags before parsing.
	registerUpstreamFlags(flag.CommandLine)

	cookieFlags()
	openidFlags()
	otelFlags()
	rateLimitFlags()
	redisFlags()
	sessionFlags()
	ssoFlags()

	flag.Parse()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			return nil, err
		}
	}

	// Bind only canonical keys to keep legacy aliases out of strict decoding.
	var bindErr error
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if isLegacyUpstreamFlag(f.Name) {
			return
		}
		if err := viper.BindPFlag(f.Name, f); err != nil {
			bindErr = err
		}
	})
	if bindErr != nil {
		return nil, bindErr
	}

	// Canonical flags take precedence over promoted legacy flags.
	promoteLegacyUpstreamFlags(viper.GetViper(), flag.CommandLine)

	level := viper.GetString(LogLevel)
	format := viper.GetString(LogFormat)
	if err := logging.Setup(level, format); err != nil {
		return nil, err
	}

	resolveOpenIdProvider()
	resolveUpstream()
	resolveVersion()
	resolveOtel()

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

	if err := c.OpenID.Validate(); err != nil {
		return err
	}

	if err := c.SSO.Validate(c); err != nil {
		return err
	}

	if err := c.Session.Validate(); err != nil {
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

func (c *Config) AutoRefreshDisabled() bool {
	return c.SSO.Enabled && !c.Session.ForwardAuth
}

func resolveVersion() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	commit := "unknown"
	commitDate := time.Now()

	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			commit = kv.Value
		case "vcs.time":
			commitDate, _ = time.Parse(time.RFC3339, kv.Value)
		}
	}

	if len(commit) > 7 {
		commit = commit[:7]
	}

	version := fmt.Sprintf("%s-%s", commitDate.Format("2006-01-02-150405"), commit)
	viper.Set("version", version)
	logger.Infof("config: starting wonderwall version %q built with %q", version, runtime.Version())
}
