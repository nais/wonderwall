package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/client"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

func TestLoginCallback_StateMismatchError(t *testing.T) {
	t.Run("invalid state", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?state=some-other-state"
		idp, lc := newLoginCallback(t, url)
		defer idp.Close()

		err := lc.StateMismatchError()
		assert.Error(t, err)
	})

	t.Run("missing state", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback"
		idp, lc := newLoginCallback(t, url)
		defer idp.Close()

		err := lc.StateMismatchError()
		assert.Error(t, err)
	})
}

func TestLoginCallback_IdentityProviderError(t *testing.T) {
	url := mock.Ingress + "/oauth2/callback?error=invalid_client&error_description=client%20authenticaion%20failed"

	idp, lc := newLoginCallback(t, url)
	defer idp.Close()

	err := lc.IdentityProviderError()
	assert.Error(t, err)
}

func TestLoginCallback_RedeemTokens(t *testing.T) {
	url := mock.Ingress + "/oauth2/callback?code=some-code"

	t.Run("happy path", func(t *testing.T) {
		idp, lc := newLoginCallback(t, url)
		defer idp.Close()

		tokens, err := lc.RedeemTokens(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, tokens)

		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		assert.NotEmpty(t, tokens.IDToken.GetSerialized())
		assert.NotEmpty(t, tokens.TokenType)
		assert.NotEmpty(t, tokens.Expiry)

		assert.Equal(t, "Bearer", tokens.TokenType)

		assert.True(t, time.Now().Before(tokens.Expiry))
		assert.True(t, tokens.Expiry.Before(time.Now().Add(time.Hour)))
	})

	t.Run("invalid code", func(t *testing.T) {
		idp, lc := newLoginCallback(t, url)
		defer idp.Close()
		idp.ProviderHandler.Codes = map[string]*mock.AuthorizeRequest{
			"some-other-code": {},
			"another-code":    {},
		}

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		idp, lc := newLoginCallback(t, url)
		defer idp.Close()
		idp.ProviderHandler.Codes["some-code"].Nonce = "some-other-nonce"

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("redirect_uri mismatch", func(t *testing.T) {
		idp, lc := newLoginCallback(t, url)
		defer idp.Close()
		idp.ProviderHandler.Codes["some-code"].RedirectUri = "http://not-wonderwall/oauth2/callback"

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("unexpected audience", func(t *testing.T) {
		idp, lc := newLoginCallback(t, url)
		defer idp.Close()
		idp.Cfg.OpenID.ClientID = "new-client-id"

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})
}

func newLoginCallback(t *testing.T, url string) (*mock.IdentityProvider, *client.LoginCallback) {
	idp := mock.NewIdentityProvider(mock.Config())
	req := idp.GetRequest(url)

	redirect, err := urlpkg.LoginCallback(req)
	assert.NoError(t, err)

	idp.ProviderHandler.Codes = map[string]*mock.AuthorizeRequest{
		"some-code": {
			ClientID:      idp.OpenIDConfig.Client().ClientID(),
			CodeChallenge: client.CodeChallenge("some-verifier"),
			Nonce:         "some-nonce",
			RedirectUri:   redirect,
		},
	}

	cookie := &openid.LoginCookie{
		State:        "some-state",
		Nonce:        "some-nonce",
		CodeVerifier: "some-verifier",
		RedirectURI:  redirect,
	}

	loginCallback, err := idp.RelyingPartyHandler.Client.LoginCallback(req, cookie)
	assert.NoError(t, err)

	return idp, loginCallback
}
