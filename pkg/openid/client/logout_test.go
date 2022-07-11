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

func TestLogout_CanonicalRedirect(t *testing.T) {
	logout := newLogout(t)
	canonicalRedirect := logout.CanonicalRedirect()

	assert.Equal(t, PostLogoutRedirectURI, canonicalRedirect)
}

func TestLogout_Cookie(t *testing.T) {
	logout := newLogout(t)
	cookie := logout.Cookie()

	assert.NotNil(t, cookie)
	assert.NotEmpty(t, cookie.State)
	assert.NotEmpty(t, cookie.RedirectTo)
}

func TestLogout_SingleLogoutURL(t *testing.T) {
	t.Run("with id_token", func(t *testing.T) {
		logout := newLogout(t)
		cookie := logout.Cookie()

		state := cookie.State
		idToken := "some-id-token"

		raw := logout.SingleLogoutURL(idToken)
		assert.NotEmpty(t, raw)

		logoutUrl, err := url.Parse(raw)
		assert.NoError(t, err)

		query := logoutUrl.Query()
		assert.Len(t, query, 3)

		assert.Contains(t, query, "id_token_hint")
		assert.Equal(t, idToken, query.Get("id_token_hint"))

		assert.Contains(t, query, "state")
		assert.Equal(t, state, query.Get("state"))

		assert.Contains(t, query, "post_logout_redirect_uri")
		assert.Equal(t, LogoutCallbackURI, query.Get("post_logout_redirect_uri"))

		logoutUrl.RawQuery = ""
		assert.Equal(t, EndSessionEndpoint, logoutUrl.String())
	})

	t.Run("without id_token", func(t *testing.T) {
		logout := newLogout(t)
		cookie := logout.Cookie()

		state := cookie.State
		idToken := ""

		raw := logout.SingleLogoutURL(idToken)
		assert.NotEmpty(t, raw)

		logoutUrl, err := url.Parse(raw)
		assert.NoError(t, err)

		query := logoutUrl.Query()
		assert.Len(t, query, 2)

		assert.NotContains(t, query, "id_token_hint")
		assert.Equal(t, idToken, query.Get("id_token_hint"))

		assert.Contains(t, query, "state")
		assert.Equal(t, state, query.Get("state"))

		assert.Contains(t, query, "post_logout_redirect_uri")
		assert.Equal(t, LogoutCallbackURI, query.Get("post_logout_redirect_uri"))

		logoutUrl.RawQuery = ""
		assert.Equal(t, EndSessionEndpoint, logoutUrl.String())
	})
}

func newLogout(t *testing.T) client.Logout {
	cfg := mock.NewTestConfiguration(mock.Config())
	cfg.ClientConfig.LogoutCallbackURI = LogoutCallbackURI
	cfg.ClientConfig.PostLogoutRedirectURI = PostLogoutRedirectURI
	cfg.ProviderConfig.EndSessionEndpoint = EndSessionEndpoint

	logout, err := newTestClientWithConfig(cfg).Logout()
	assert.NoError(t, err)

	return logout
}
