package handler_test

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
)

func TestFrontChannelLogout(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.OpenIDConfig.TestProvider.WithFrontChannelLogoutSupport()
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	sessionCookie := login(t, rpClient, idp)

	// Trigger front-channel logout
	sid := func(r *http.Request) string {
		ciphertext, err := base64.RawURLEncoding.DecodeString(sessionCookie.Value)
		assert.NoError(t, err)

		sessionKey, err := idp.RelyingPartyHandler.GetCrypter().Decrypt(ciphertext)
		assert.NoError(t, err)

		data, err := idp.RelyingPartyHandler.GetSessions().Get(r, string(sessionKey))
		assert.NoError(t, err)

		return data.ExternalSessionID
	}

	frontchannelLogoutURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/logout/frontchannel")
	assert.NoError(t, err)

	req := idp.GetRequest(frontchannelLogoutURL.String())

	values := url.Values{}
	values.Add("sid", sid(req))
	values.Add("iss", idp.OpenIDConfig.Provider().Issuer())
	frontchannelLogoutURL.RawQuery = values.Encode()

	resp := get(t, rpClient, frontchannelLogoutURL.String())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
