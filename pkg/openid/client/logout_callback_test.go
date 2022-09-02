package client_test

import (
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
		cfg.OpenID.PostLogoutRedirectURI = ""

		lc := newLogoutCallback(cfg)

		uri := lc.PostLogoutRedirectURI()
		assert.NotEmpty(t, uri)
		assert.Equal(t, mock.Ingress, uri)
	})
}

func newLogoutCallback(cfg *config.Config) *client.LogoutCallback {
	openidCfg := mock.NewTestConfiguration(cfg)
	ingresses := mock.Ingresses(cfg)
	req := mock.NewGetRequest(mock.Ingress+"/oauth2/logout/callback", ingresses)
	return newTestClientWithConfig(openidCfg).LogoutCallback(req)
}
