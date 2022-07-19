package client_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestLogoutCallback_PostLogoutRedirectURI(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		lc, cfg := newLogoutCallback()
		cfg.ClientConfig.PostLogoutRedirectURI = "http://some-fancy-logout-page"

		uri := lc.PostLogoutRedirectURI()
		assert.NotEmpty(t, uri)
		assert.Equal(t, "http://some-fancy-logout-page", uri)
	})

	t.Run("empty preconfigured post-logout redirect uri", func(t *testing.T) {
		lc, cfg := newLogoutCallback()
		cfg.ClientConfig.PostLogoutRedirectURI = ""
		cfg.WonderwallConfig.Ingress = "http://wonderwall"

		uri := lc.PostLogoutRedirectURI()
		assert.NotEmpty(t, uri)
		assert.Equal(t, "http://wonderwall", uri)
	})
}

func newLogoutCallback() (client.LogoutCallback, *mock.Configuration) {
	req := httptest.NewRequest("GET", "http://wonderwall/oauth2/logout/callback", nil)

	cfg := mock.NewTestConfiguration(mock.Config())
	return newTestClientWithConfig(cfg).LogoutCallback(req), cfg
}
