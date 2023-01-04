package handler_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	urlpkg "github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/mock"
)

func TestLogout(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := selfInitiatedLogout(t, rpClient, idp)

	// Get endsession endpoint after local logout
	endsessionURL := resp.Location

	idpserverURL, err := url.Parse(idp.ProviderServer.URL)
	assert.NoError(t, err)

	req := idp.GetRequest(idp.RelyingPartyServer.URL + "/oauth2/logout/callback")
	expectedLogoutCallbackURL, err := urlpkg.LogoutCallbackURL(req)
	assert.NoError(t, err)

	endsessionParams := endsessionURL.Query()
	assert.Equal(t, idpserverURL.Host, endsessionURL.Host)
	assert.Equal(t, "/endsession", endsessionURL.Path)
	assert.Equal(t, []string{expectedLogoutCallbackURL}, endsessionParams["post_logout_redirect_uri"])
	assert.NotEmpty(t, endsessionParams["id_token_hint"])
}

func TestLogoutLocal(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	localLogout(t, rpClient, idp)
}
