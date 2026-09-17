package config

import (
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Upstream struct {
	AccessLogs     bool   `json:"access-logs"`
	Host           string `json:"host"`
	IP             string `json:"ip"`
	Port           int    `json:"port"`
	IncludeIDToken bool   `json:"include-id-token"`
	DPoP           bool   `json:"dpop"`
}

const (
	UpstreamAccessLogs     = "upstream.access-logs"
	UpstreamHost           = "upstream.host"
	UpstreamIP             = "upstream.ip"
	UpstreamPort           = "upstream.port"
	UpstreamIncludeIDToken = "upstream.include-id-token"
	UpstreamDPoP           = "upstream.dpop"
)

var legacyUpstreamFlags = map[string]string{
	"upstream-access-logs":      UpstreamAccessLogs,
	"upstream-host":             UpstreamHost,
	"upstream-ip":               UpstreamIP,
	"upstream-port":             UpstreamPort,
	"upstream-include-id-token": UpstreamIncludeIDToken,
}

func (c *Config) validateUpstream() error {
	if c.Upstream.DPoP {
		if c.SSO.Enabled && c.SSO.Mode == SSOModeProxy {
			return fmt.Errorf("%q is not supported in SSO proxy mode", UpstreamDPoP)
		}
		if c.OpenID.ClientJWK == "" {
			return fmt.Errorf("%q requires %q", UpstreamDPoP, OpenIDClientJWK)
		}
	}

	if c.Upstream.IP == "" && c.Upstream.Port == 0 {
		return nil
	}
	if c.Upstream.IP == "" {
		return fmt.Errorf("%q must be set when %q is set", UpstreamIP, UpstreamPort)
	}
	if c.Upstream.Port == 0 {
		return fmt.Errorf("%q must be set when %q is set", UpstreamPort, UpstreamIP)
	}
	if c.Upstream.Port < 1 || c.Upstream.Port > 65535 {
		return fmt.Errorf("%q must be in valid range (between '1' and '65535', was '%d')", UpstreamPort, c.Upstream.Port)
	}
	return nil
}

func resolveUpstream() {
	ip := viper.GetString(UpstreamIP)
	port := viper.GetInt(UpstreamPort)
	host := viper.GetString(UpstreamHost)

	if ip != "" && port > 0 {
		resolved := fmt.Sprintf("%s:%d", ip, port)
		logger.Debugf("%q and %q were set; overriding %q from %q to %q", UpstreamIP, UpstreamPort, UpstreamHost, host, resolved)
		viper.Set(UpstreamHost, resolved)
	}
}

func registerUpstreamFlags(flags *flag.FlagSet) {
	flags.Bool(UpstreamAccessLogs, false, "Enable access logs for upstream requests.")
	flags.String(UpstreamHost, "127.0.0.1:8080", "Address of upstream host.")
	flags.String(UpstreamIP, "", "IP of upstream host. Overrides 'upstream.host' if set.")
	flags.Int(UpstreamPort, 0, "Port of upstream host. Overrides 'upstream.host' if set.")
	flags.Bool(UpstreamIncludeIDToken, false, "Include ID token in upstream requests in 'X-Wonderwall-Id-Token' header.")
	flags.Bool(UpstreamDPoP, false, "Send DPoP-bound access tokens to the upstream with a DPoP proof instead of as bearer tokens.")

	flags.Bool("upstream-access-logs", false, "Deprecated alias for --upstream.access-logs.")
	flags.String("upstream-host", "", "Deprecated alias for --upstream.host.")
	flags.String("upstream-ip", "", "Deprecated alias for --upstream.ip.")
	flags.Int("upstream-port", 0, "Deprecated alias for --upstream.port.")
	flags.Bool("upstream-include-id-token", false, "Deprecated alias for --upstream.include-id-token.")

	for legacy, canonical := range legacyUpstreamFlags {
		_ = flags.MarkDeprecated(legacy, fmt.Sprintf("use --%s instead", canonical))
	}
}

func promoteLegacyUpstreamFlags(v *viper.Viper, flags *flag.FlagSet) {
	for legacy, canonical := range legacyUpstreamFlags {
		if flags.Changed(legacy) && !flags.Changed(canonical) {
			v.Set(canonical, flags.Lookup(legacy).Value.String())
		}
	}
}

func isLegacyUpstreamFlag(name string) bool {
	_, ok := legacyUpstreamFlags[name]
	return ok
}
