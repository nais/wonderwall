package config_test

import (
	"testing"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	type test struct {
		name   string
		mutate func(cfg *config.Config)
	}

	run := func(name string, base *config.Config, errorCases []test) {
		t.Run(name, func(t *testing.T) {
			t.Run("happy path", func(t *testing.T) {
				assert.NoError(t, base.Validate())
			})

			for _, tt := range errorCases {
				t.Run(tt.name, func(t *testing.T) {
					cfg := *base
					tt.mutate(&cfg)
					assert.Error(t, cfg.Validate())
				})
			}
		})
	}

	base, err := config.Initialize()
	require.NoError(t, err)

	run("default", base, []test{
		{
			"invalid value for cookie.same-site",
			func(cfg *config.Config) {
				cfg.Cookie.SameSite = "invalid"
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
		{
			"secure cookies cannot be disabled for non-localhost ingress",
			func(cfg *config.Config) {
				cfg.Cookie.Secure = false
				cfg.Ingresses = []string{"http://not-localhost.example"}
			},
		},
		{
			"secure cookies cannot be disabled for secure ingress",
			func(cfg *config.Config) {
				cfg.Cookie.Secure = false
				cfg.Ingresses = []string{"https://localhost:3000"}
			},
		},
	})

	server := *base
	server.SSO.Enabled = true
	server.SSO.Mode = config.SSOModeServer
	server.SSO.Domain = "example.com"
	server.SSO.SessionCookieName = "some-cookie"
	server.SSO.ServerDefaultRedirectURL = "https://default.local"
	server.Session.RefreshAuto = false
	server.Redis.Address = "localhost:6379"

	run("sso server", &server, []test{
		{
			"missing redis",
			func(cfg *config.Config) {
				cfg.Redis = config.Redis{}
			},
		},
		{
			"missing cookie name",
			func(cfg *config.Config) {
				cfg.SSO.SessionCookieName = ""
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
			"invalid default redirect url",
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

	proxy := *base
	proxy.SSO.Enabled = true
	proxy.SSO.Mode = config.SSOModeProxy
	proxy.SSO.ServerURL = "https://sso-server.local"
	proxy.SSO.SessionCookieName = "some-cookie"
	proxy.Session.RefreshAuto = false
	proxy.Redis.Address = "localhost:6379"

	run("sso proxy", &proxy, []test{
		{
			"missing redis",
			func(cfg *config.Config) {
				cfg.Redis = config.Redis{}
			},
		},
		{
			"missing cookie name",
			func(cfg *config.Config) {
				cfg.SSO.SessionCookieName = ""
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
