package client_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

const (
	LogoutCallbackURI     = "http://wonderwall/oauth2/logout/callback"
	PostLogoutRedirectURI = "http://some-other-url"
	EndSessionEndpoint    = "http://provider/endsession"
)

func TestLogout_SingleLogoutURL(t *testing.T) {
	t.Run("with id_token", func(t *testing.T) {
		logout := newLogout()
		idToken := "some-id-token"

		raw := logout.SingleLogoutURL(idToken)
		assert.NotEmpty(t, raw)

		logoutUrl, err := url.Parse(raw)
		assert.NoError(t, err)

		query := logoutUrl.Query()
		assert.Len(t, query, 2)

		assert.Contains(t, query, "id_token_hint")
		assert.Equal(t, idToken, query.Get("id_token_hint"))

		assert.Contains(t, query, "post_logout_redirect_uri")
		assert.Equal(t, LogoutCallbackURI, query.Get("post_logout_redirect_uri"))

		logoutUrl.RawQuery = ""
		assert.Equal(t, EndSessionEndpoint, logoutUrl.String())
	})

	t.Run("without id_token", func(t *testing.T) {
		logout := newLogout()
		idToken := ""

		raw := logout.SingleLogoutURL(idToken)
		assert.NotEmpty(t, raw)

		logoutUrl, err := url.Parse(raw)
		assert.NoError(t, err)

		query := logoutUrl.Query()
		assert.Len(t, query, 1)

		assert.NotContains(t, query, "id_token_hint")
		assert.Equal(t, idToken, query.Get("id_token_hint"))

		assert.Contains(t, query, "post_logout_redirect_uri")
		assert.Equal(t, LogoutCallbackURI, query.Get("post_logout_redirect_uri"))

		logoutUrl.RawQuery = ""
		assert.Equal(t, EndSessionEndpoint, logoutUrl.String())
	})
}

func newLogout() client.Logout {
	cfg := mock.Config()
	cfg.OpenID.PostLogoutRedirectURI = PostLogoutRedirectURI

	openidCfg := mock.NewTestConfiguration(cfg)
	openidCfg.TestClient.SetLogoutCallbackURI(LogoutCallbackURI)
	openidCfg.TestProvider.SetEndSessionEndpoint(EndSessionEndpoint)

	return newTestClientWithConfig(openidCfg).Logout()
}
