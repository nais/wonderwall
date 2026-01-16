package client_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

const (
	LogoutCallbackURI     = mock.Ingress + "/oauth2/logout/callback"
	PostLogoutRedirectURI = "http://some-other-url"
	EndSessionEndpoint    = "http://provider/endsession"
)

func TestLogout_SingleLogoutURL(t *testing.T) {
	t.Run("with id_token", func(t *testing.T) {
		logout := newLogout(t)
		idToken := "some-id-token"
		state := logout.Cookie.State

		raw := logout.SingleLogoutURL(idToken)
		assert.NotEmpty(t, raw)

		logoutUrl, err := url.Parse(raw)
		assert.NoError(t, err)

		query := logoutUrl.Query()
		assert.Len(t, query, 3)

		assert.Contains(t, query, "id_token_hint")
		assert.Equal(t, idToken, query.Get("id_token_hint"))

		assert.Contains(t, query, "post_logout_redirect_uri")
		assert.Equal(t, LogoutCallbackURI, query.Get("post_logout_redirect_uri"))

		assert.Contains(t, query, "state")
		assert.Equal(t, state, query.Get("state"))

		logoutUrl.RawQuery = ""
		assert.Equal(t, EndSessionEndpoint, logoutUrl.String())
	})

	t.Run("without id_token", func(t *testing.T) {
		logout := newLogout(t)
		idToken := ""
		state := logout.Cookie.State

		raw := logout.SingleLogoutURL(idToken)
		assert.NotEmpty(t, raw)

		logoutUrl, err := url.Parse(raw)
		assert.NoError(t, err)

		query := logoutUrl.Query()
		assert.Len(t, query, 2)

		assert.NotContains(t, query, "id_token_hint")
		assert.Equal(t, idToken, query.Get("id_token_hint"))

		assert.Contains(t, query, "post_logout_redirect_uri")
		assert.Equal(t, LogoutCallbackURI, query.Get("post_logout_redirect_uri"))

		assert.Contains(t, query, "state")
		assert.Equal(t, state, query.Get("state"))

		logoutUrl.RawQuery = ""
		assert.Equal(t, EndSessionEndpoint, logoutUrl.String())
	})

	t.Run("with logout_hint claim", func(t *testing.T) {
		logout := newLogout(t)
		logout.LogoutHint = "some-logout-hint"
		idToken := ""
		state := logout.Cookie.State

		raw := logout.SingleLogoutURL(idToken)
		assert.NotEmpty(t, raw)

		logoutUrl, err := url.Parse(raw)
		assert.NoError(t, err)

		query := logoutUrl.Query()
		assert.Len(t, query, 3)

		assert.Contains(t, query, "logout_hint")
		assert.Equal(t, logout.LogoutHint, query.Get("logout_hint"))

		assert.NotContains(t, query, "id_token_hint")
		assert.Equal(t, idToken, query.Get("id_token_hint"))

		assert.Contains(t, query, "post_logout_redirect_uri")
		assert.Equal(t, LogoutCallbackURI, query.Get("post_logout_redirect_uri"))

		assert.Contains(t, query, "state")
		assert.Equal(t, state, query.Get("state"))

		logoutUrl.RawQuery = ""
		assert.Equal(t, EndSessionEndpoint, logoutUrl.String())
	})
}

func newLogout(t *testing.T) *client.Logout {
	cfg := mock.Config()

	openidCfg := mock.NewTestConfiguration(cfg)
	openidCfg.TestClient.SetPostLogoutRedirectURI(PostLogoutRedirectURI)
	openidCfg.TestProvider.SetEndSessionEndpoint(EndSessionEndpoint)
	ingresses := mock.Ingresses(cfg)

	req := mock.NewGetRequest(mock.Ingress+"/oauth2/logout", ingresses)

	logout, err := newTestClientWithConfig(openidCfg).Logout(req)
	assert.NoError(t, err)

	return logout
}
