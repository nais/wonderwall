package client_test

import (
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
	t.Run("happy path", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state"
		tokens, err := newLoginCallback(t, url, nil)
		require.NoError(t, err)
		require.NotNil(t, tokens)

		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		assert.NotEmpty(t, tokens.IDToken.Serialized())
		assert.NotEmpty(t, tokens.TokenType)
		assert.NotEmpty(t, tokens.Expiry)

		assert.Equal(t, "Bearer", tokens.TokenType)

		assert.True(t, time.Now().Before(tokens.Expiry))
		assert.True(t, tokens.Expiry.Before(time.Now().Add(time.Hour)))
	})

	t.Run("invalid state", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?state=some-other-state"
		_, err := newLoginCallback(t, url, nil)
		assert.ErrorIs(t, err, client.ErrCallbackInvalidState)
	})

	t.Run("missing state", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback"
		_, err := newLoginCallback(t, url, nil)
		assert.ErrorIs(t, err, client.ErrCallbackInvalidState)
	})

	t.Run("identity provider error", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?error=invalid_client&error_description=client%20authenticaion%20failed"
		idp := mock.NewIdentityProvider(mock.Config())
		defer idp.Close()

		_, err := newLoginCallback(t, url, nil)
		assert.ErrorIs(t, err, client.ErrCallbackIdentityProvider)
	})

	t.Run("supports authorization response with iss parameter", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state&iss=https://some-issuer"
		_, err := newLoginCallback(t, url, func(idp *mock.IdentityProvider) {
			idp.OpenIDConfig.TestProvider.SetIssuer("https://some-issuer")
			idp.OpenIDConfig.TestProvider.WithAuthorizationResponseIssParameterSupported()
		})
		assert.NoError(t, err)
	})

	t.Run("missing issuer", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state"
		_, err := newLoginCallback(t, url, func(idp *mock.IdentityProvider) {
			idp.OpenIDConfig.TestProvider.WithAuthorizationResponseIssParameterSupported()
		})
		assert.ErrorIs(t, err, client.ErrCallbackInvalidIssuer)
		assert.ErrorContains(t, err, "missing issuer parameter")
	})

	t.Run("invalid issuer", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state&iss=https://wrong-issuer"
		_, err := newLoginCallback(t, url, func(idp *mock.IdentityProvider) {
			idp.OpenIDConfig.TestProvider.SetIssuer("https://some-issuer")
			idp.OpenIDConfig.TestProvider.WithAuthorizationResponseIssParameterSupported()
		})
		assert.ErrorIs(t, err, client.ErrCallbackInvalidIssuer)
		assert.ErrorContains(t, err, "issuer mismatch: expected \"https://some-issuer\", got \"https://wrong-issuer\"")
	})

	t.Run("invalid code", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state"
		tokens, err := newLoginCallback(t, url, func(idp *mock.IdentityProvider) {
			idp.ProviderHandler.Codes = map[string]*mock.AuthorizeRequest{
				"some-other-code": {},
				"another-code":    {},
			}
		})

		assert.ErrorIs(t, err, client.ErrCallbackRedeemTokens)
		assert.Nil(t, tokens)
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state"
		tokens, err := newLoginCallback(t, url, func(idp *mock.IdentityProvider) {
			idp.ProviderHandler.Codes["some-code"].Nonce = "some-other-nonce"
		})
		assert.ErrorIs(t, err, client.ErrCallbackRedeemTokens)
		assert.Nil(t, tokens)
	})

	t.Run("redirect_uri mismatch", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state"
		tokens, err := newLoginCallback(t, url, func(idp *mock.IdentityProvider) {
			idp.ProviderHandler.Codes["some-code"].RedirectUri = "http://not-wonderwall/oauth2/callback"
		})
		assert.ErrorIs(t, err, client.ErrCallbackRedeemTokens)
		assert.Nil(t, tokens)
	})

	t.Run("unexpected audience", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state"
		tokens, err := newLoginCallback(t, url, func(idp *mock.IdentityProvider) {
			idp.Cfg.OpenID.ClientID = "new-client-id"
		})
		assert.ErrorIs(t, err, client.ErrCallbackRedeemTokens)
		assert.Nil(t, tokens)
	})

	t.Run("invalid acr", func(t *testing.T) {
		url := mock.Ingress + "/oauth2/callback?code=some-code&state=some-state"
		tokens, err := newLoginCallback(t, url, func(idp *mock.IdentityProvider) {
			idp.ProviderHandler.Codes["some-code"].AcrLevel = "some-invalid-acr"
		})
		assert.ErrorIs(t, err, client.ErrCallbackRedeemTokens)
		assert.ErrorContains(t, err, "invalid acr: got \"some-invalid-acr\", expected \"some-acr\"")
		assert.Nil(t, tokens)
	})
}

func newLoginCallback(t *testing.T, url string, mutateFn func(*mock.IdentityProvider)) (*openid.Tokens, error) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

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

	if mutateFn != nil {
		mutateFn(idp)
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
