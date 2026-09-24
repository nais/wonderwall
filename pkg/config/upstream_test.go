package config

import (
	"testing"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPromoteLegacyUpstreamFlags(t *testing.T) {
	tests := []struct {
		name      string
		argument  string
		legacy    string
		canonical string
		expected  string
	}{
		{"access logs", "--upstream-access-logs", "upstream-access-logs", UpstreamAccessLogs, "true"},
		{"host", "--upstream-host=legacy:8080", "upstream-host", UpstreamHost, "legacy:8080"},
		{"ip", "--upstream-ip=192.0.2.1", "upstream-ip", UpstreamIP, "192.0.2.1"},
		{"port", "--upstream-port=8080", "upstream-port", UpstreamPort, "8080"},
		{"include ID token", "--upstream-include-id-token", "upstream-include-id-token", UpstreamIncludeIDToken, "true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			registerUpstreamFlags(flags)
			require.NoError(t, flags.Parse([]string{tt.argument}))

			v := viper.New()
			require.NoError(t, v.BindPFlag(tt.canonical, flags.Lookup(tt.canonical)))
			promoteLegacyUpstreamFlags(v, flags)

			assert.Equal(t, tt.expected, v.GetString(tt.canonical))
			assert.NotEmpty(t, flags.Lookup(tt.legacy).Deprecated)
		})
	}

	t.Run("canonical flag wins", func(t *testing.T) {
		flags := flag.NewFlagSet("test", flag.ContinueOnError)
		registerUpstreamFlags(flags)
		require.NoError(t, flags.Parse([]string{
			"--upstream-host=legacy:8080",
			"--upstream.host=canonical:8080",
		}))

		v := viper.New()
		require.NoError(t, v.BindPFlag(UpstreamHost, flags.Lookup(UpstreamHost)))
		promoteLegacyUpstreamFlags(v, flags)

		assert.Equal(t, "canonical:8080", v.GetString(UpstreamHost))
	})
}
