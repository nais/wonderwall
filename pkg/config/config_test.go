package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/pkg/config"
)

func TestConfig_Validate(t *testing.T) {
	fixture, err := config.Initialize()
	require.NoError(t, err)

	deepcopy := func(src *config.Config) *config.Config {
		c := *src
		return &c
	}

	type test struct {
		name   string
		mutate func(cfg *config.Config)
	}

	run := func(t *testing.T, name string, base *config.Config, tests []test) {
		t.Run(name, func(t *testing.T) {
			t.Run("happy path", func(t *testing.T) {
				err = base.Validate()
				assert.NoError(t, err)
			})

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					cfg := deepcopy(base)
					tt.mutate(cfg)

					err = cfg.Validate()
					assert.Error(t, err)
				})
			}
		})
	}

	run(t, "default", fixture, []test{
		{
			"invalid value for cookie-same-site",
			func(cfg *config.Config) {
				cfg.CookieSameSite = "invalid"
			},
		},
		{
			"session inactivity without session refresh",
			func(cfg *config.Config) {
				cfg.Session.Inactivity = true
				cfg.Session.Refresh = false
			},
		},
		{
			"session auto refresh without session refresh",
			func(cfg *config.Config) {
				cfg.Session.RefreshAuto = true
				cfg.Session.Refresh = false
			},
		},
		{
			"upstream ip must be set if port is set",
			func(cfg *config.Config) {
				cfg.UpstreamIP = ""
				cfg.UpstreamPort = 8080
			},
		},
		{
			"upstream port must be set if ip is set",
			func(cfg *config.Config) {
				cfg.UpstreamIP = "127.0.0.1"
				cfg.UpstreamPort = 0
			},
		},
		{
			"upstream port must not exceed 65535",
			func(cfg *config.Config) {
				cfg.UpstreamIP = "127.0.0.1"
				cfg.UpstreamPort = 65536
			},
		},
		{
			"upstream port must not be negative",
			func(cfg *config.Config) {
				cfg.UpstreamIP = "127.0.0.1"
				cfg.UpstreamPort = -1
			},
		},
		{
			"shutdown graceful period must be greater than wait before period",
			func(cfg *config.Config) {
				cfg.ShutdownGracefulPeriod = 1
				cfg.ShutdownWaitBeforePeriod = 1
			},
		},
	})

	server := deepcopy(fixture)
	server.SSO.Enabled = true
	server.SSO.Mode = config.SSOModeServer
	server.SSO.Domain = "example.com"
	server.SSO.SessionCookieName = "some-cookie"
	server.SSO.ServerDefaultRedirectURL = "https://default.local"
	server.Session.RefreshAuto = false
	server.Redis.Address = "localhost:6379"

	run(t, "sso server", server, []test{
		{
			"missing redis",
			func(cfg *config.Config) {
				cfg.Redis = config.Redis{}
			},
		},
		{
			"with session auto refresh",
			func(cfg *config.Config) {
				cfg.Session.RefreshAuto = true
			},
		},
		{
			"missing session cookie name",
			func(cfg *config.Config) {
				cfg.SSO.SessionCookieName = ""
			},
		},
		{
			"missing domain",
			func(cfg *config.Config) {
				cfg.SSO.Domain = ""
			},
		},
		{
			"invalid server default redirect url",
			func(cfg *config.Config) {
				cfg.SSO.ServerDefaultRedirectURL = "invalid"
			},
		},
		{
			"invalid mode",
			func(cfg *config.Config) {
				cfg.SSO.Mode = "invalid"
			},
		},
	})

	proxy := deepcopy(fixture)
	proxy.SSO.Enabled = true
	proxy.SSO.Mode = config.SSOModeProxy
	proxy.SSO.ServerURL = "https://sso-server.local"
	proxy.SSO.SessionCookieName = "some-cookie"
	proxy.Session.RefreshAuto = false
	proxy.Redis.Address = "localhost:6379"

	run(t, "sso proxy", proxy, []test{
		{
			"missing redis",
			func(cfg *config.Config) {
				cfg.Redis = config.Redis{}
			},
		},
		{
			"with session auto refresh",
			func(cfg *config.Config) {
				cfg.Session.RefreshAuto = true
			},
		},
		{
			"missing session cookie name",
			func(cfg *config.Config) {
				cfg.SSO.SessionCookieName = ""
			},
		},
		{
			"invalid server url",
			func(cfg *config.Config) {
				cfg.SSO.ServerURL = "invalid"
			},
		},
		{
			"invalid mode",
			func(cfg *config.Config) {
				cfg.SSO.Mode = "invalid"
			},
		},
	})
}
