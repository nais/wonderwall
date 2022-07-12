package client_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestLogoutCallback_PostLogoutRedirectURI(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		lc, cfg := newLogoutCallback(t)
		cfg.ClientConfig.PostLogoutRedirectURI = "http://some-fancy-logout-page"

		uri := lc.PostLogoutRedirectURI()
		assert.NotEmpty(t, uri)
		assert.Equal(t, "http://some-fancy-logout-page", uri)
	})

	t.Run("empty preconfigured post-logout redirect uri", func(t *testing.T) {
		lc, cfg := newLogoutCallback(t)
		cfg.ClientConfig.PostLogoutRedirectURI = ""
		cfg.WonderwallConfig.Ingress = "http://wonderwall"

		uri := lc.PostLogoutRedirectURI()
		assert.NotEmpty(t, uri)
		assert.Equal(t, "http://wonderwall", uri)
	})
}

func newLogoutCallback(t *testing.T) (client.LogoutCallback, mock.Configuration) {
	req, err := http.NewRequest("GET", "http://wonderwall/oauth2/logout/callback", nil)
	assert.NoError(t, err)

	cfg := mock.NewTestConfiguration(mock.Config())
	return newTestClientWithConfig(cfg).LogoutCallback(req), cfg
}
