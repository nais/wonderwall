package client_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestLogoutCallback_PostLogoutRedirectURI(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		cfg := mock.Config()
		cfg.OpenID.PostLogoutRedirectURI = "http://some-fancy-logout-page"

		lc := newLogoutCallback(cfg)

		uri := lc.PostLogoutRedirectURI()
		assert.NotEmpty(t, uri)
		assert.Equal(t, "http://some-fancy-logout-page", uri)
	})

	t.Run("empty preconfigured post-logout redirect uri", func(t *testing.T) {
		cfg := mock.Config()
		cfg.Ingress = "http://wonderwall"
		cfg.OpenID.PostLogoutRedirectURI = ""

		lc := newLogoutCallback(cfg)

		uri := lc.PostLogoutRedirectURI()
		assert.NotEmpty(t, uri)
		assert.Equal(t, "http://wonderwall", uri)
	})
}

func newLogoutCallback(cfg *config.Config) client.LogoutCallback {
	req := httptest.NewRequest("GET", "http://wonderwall/oauth2/logout/callback", nil)
	openidCfg := mock.NewTestConfiguration(cfg)
	return newTestClientWithConfig(openidCfg).LogoutCallback(req, cfg.Ingress)
}
