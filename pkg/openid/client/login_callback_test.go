package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/client"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

func TestLoginCallback(t *testing.T) {
	t.Run("invalid state", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?state=some-other-state"
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		assert.Nil(t, lc)
		assert.ErrorIs(t, err, client.ErrCallbackInvalidState)
	})

	t.Run("missing state", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback"
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		assert.Nil(t, lc)
		assert.ErrorIs(t, err, client.ErrCallbackInvalidState)
	})

	t.Run("identity provider error", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?error=invalid_client&error_description=client%20authenticaion%20failed"

		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		assert.Nil(t, lc)
		assert.ErrorIs(t, err, client.ErrCallbackIdentityProvider)
	})

	t.Run("supports authorization response with iss parameter", func(t *testing.T) {
		idp := mock.NewIdentityProvider(mock.Config())
		idp.OpenIDConfig.TestProvider.WithAuthorizationResponseIssParameterSupported()

		for _, tt := range []struct {
			name       string
			iss        string
			assertions func(t *testing.T, lc *client.LoginCallback, err error)
		}{
			{
				name: "happy path",
				iss:  idp.OpenIDConfig.TestProvider.Issuer(),
				assertions: func(t *testing.T, lc *client.LoginCallback, err error) {
					assert.NotNil(t, lc)
					assert.NoError(t, err)
				},
			},
			{
				name: "missing issuer",
				iss:  "",
				assertions: func(t *testing.T, lc *client.LoginCallback, err error) {
					assert.Nil(t, lc)
					assert.ErrorIs(t, err, client.ErrCallbackInvalidIssuer)
				},
			},
			{
				name: "wrong issuer",
				iss:  "https://wrong-issuer",
				assertions: func(t *testing.T, lc *client.LoginCallback, err error) {
					assert.Nil(t, lc)
					assert.ErrorIs(t, err, client.ErrCallbackInvalidIssuer)
				},
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				url := mock.Ingress + "/oauth2/callback?state=some-state"
				if tt.iss != "" {
					url += "&iss=" + tt.iss
				}
				defer idp.Close()

				lc, err := newLoginCallback(t, idp, url)
				tt.assertions(t, lc, err)
			})
		}
	})
}

func TestLoginCallback_RedeemTokens(t *testing.T) {
	url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state"

	t.Run("happy path", func(t *testing.T) {
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		require.NoError(t, err)
		require.NotNil(t, lc)

		tokens, err := lc.RedeemTokens(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, tokens)

		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		assert.NotEmpty(t, tokens.IDToken.Serialized())
		assert.NotEmpty(t, tokens.TokenType)
		assert.NotEmpty(t, tokens.Expiry)

		assert.Equal(t, "Bearer", tokens.TokenType)

		assert.True(t, time.Now().Before(tokens.Expiry))
		assert.True(t, tokens.Expiry.Before(time.Now().Add(time.Hour)))
	})

	t.Run("invalid code", func(t *testing.T) {
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		require.NoError(t, err)
		require.NotNil(t, lc)
		idp.ProviderHandler.Codes = map[string]*mock.AuthorizeRequest{
			"some-other-code": {},
			"another-code":    {},
		}

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		require.NoError(t, err)
		require.NotNil(t, lc)
		idp.ProviderHandler.Codes["some-code"].Nonce = "some-other-nonce"

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("redirect_uri mismatch", func(t *testing.T) {
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		require.NoError(t, err)
		require.NotNil(t, lc)
		idp.ProviderHandler.Codes["some-code"].RedirectUri = "http://not-wonderwall/oauth2/callback"

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("unexpected audience", func(t *testing.T) {
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		require.NoError(t, err)
		require.NotNil(t, lc)
		idp.Cfg.OpenID.ClientID = "new-client-id"

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("invalid acr", func(t *testing.T) {
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		lc, err := newLoginCallback(t, idp, url)
		require.NoError(t, err)
		require.NotNil(t, lc)
		idp.ProviderHandler.Codes["some-code"].AcrLevel = "some-invalid-acr"

		tokens, err := lc.RedeemTokens(context.Background())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid acr: got \"some-invalid-acr\", expected \"some-acr\"")
		assert.Nil(t, tokens)
	})
}

func newLoginCallback(t *testing.T, idp *mock.IdentityProvider, url string) (*client.LoginCallback, error) {
	req := idp.GetRequest(url)
	redirect, err := urlpkg.LoginCallback(req)
	assert.NoError(t, err)

	idp.ProviderHandler.Codes = map[string]*mock.AuthorizeRequest{
		"some-code": {
			AcrLevel:      "some-acr",
			ClientID:      idp.OpenIDConfig.Client().ClientID(),
			CodeChallenge: oauth2.S256ChallengeFromVerifier("some-verifier"),
			Nonce:         "some-nonce",
			RedirectUri:   redirect,
		},
	}

	cookie := &openid.LoginCookie{
		Acr:          "some-acr",
		State:        "some-state",
		Nonce:        "some-nonce",
		CodeVerifier: "some-verifier",
		RedirectURI:  redirect,
	}

	return idp.RelyingPartyHandler.Client.LoginCallback(req, cookie)
}
