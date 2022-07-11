package client_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestLoginCallback_StateMismatchError(t *testing.T) {
	cookie := &openid.LoginCookie{
		State: "some-state",
	}

	t.Run("invalid state", func(t *testing.T) {
		url := "http://wonderwall/oauth2/callback?state=some-other-state"
		idp, lc := newLoginCallback(t, url, cookie)
		defer idp.Close()

		err := lc.StateMismatchError()
		assert.Error(t, err)
	})

	t.Run("missing state", func(t *testing.T) {
		url := "http://wonderwall/oauth2/callback"
		idp, lc := newLoginCallback(t, url, cookie)
		defer idp.Close()

		err := lc.StateMismatchError()
		assert.Error(t, err)
	})
}

func TestLoginCallback_IdentityProviderError(t *testing.T) {
	cookie := &openid.LoginCookie{
		State: "some-state",
	}

	url := "http://wonderwall/oauth2/callback?error=invalid_client&error_description=client%20authenticaion%20failed"

	idp, lc := newLoginCallback(t, url, cookie)
	defer idp.Close()

	err := lc.IdentityProviderError()
	assert.Error(t, err)
}

func TestLoginCallback_ExchangeAuthCode(t *testing.T) {
	t.Run("valid code", func(t *testing.T) {
		cookie := &openid.LoginCookie{}
		url := "http://wonderwall/oauth2/callback?code=some-code"

		idp, lc := newLoginCallback(t, url, cookie)
		defer idp.Close()
		idp.ProviderHandler.Codes = map[string]mock.AuthorizeRequest{
			"some-code": {},
		}

		tokens, err := lc.ExchangeAuthCode(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, tokens)

		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		assert.NotEmpty(t, tokens.Extra("id_token"))
		assert.NotEmpty(t, tokens.TokenType)
		assert.NotEmpty(t, tokens.Expiry)

		assert.Equal(t, "Bearer", tokens.TokenType)

		assert.True(t, time.Now().Before(tokens.Expiry))
		assert.True(t, tokens.Expiry.Before(time.Now().Add(time.Hour)))
	})

	t.Run("invalid code", func(t *testing.T) {
		cookie := &openid.LoginCookie{}
		url := "http://wonderwall/oauth2/callback?code=some-code"

		idp, lc := newLoginCallback(t, url, cookie)
		defer idp.Close()
		idp.ProviderHandler.Codes = map[string]mock.AuthorizeRequest{
			"some-other-code": {},
			"another-code":    {},
		}

		tokens, err := lc.ExchangeAuthCode(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})
}

func TestLoginCallback_ProcessTokens(t *testing.T) {
	cookie := &openid.LoginCookie{
		State: "some-state",
		Nonce: "some-nonce",
	}
	url := "http://wonderwall/oauth2/callback?code=some-code"

	t.Run("happy path", func(t *testing.T) {
		idp, lc := newLoginCallback(t, url, cookie)
		defer idp.Close()
		idp.ProviderHandler.Codes["some-code"] = mock.AuthorizeRequest{
			Nonce: "some-nonce",
		}

		rawTokens, err := lc.ExchangeAuthCode(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, rawTokens)

		tokens, err := lc.ProcessTokens(context.Background(), rawTokens)
		assert.NoError(t, err)
		assert.NotNil(t, tokens)
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		idp, lc := newLoginCallback(t, url, cookie)
		defer idp.Close()
		idp.ProviderHandler.Codes["some-code"] = mock.AuthorizeRequest{
			Nonce: "some-other-nonce",
		}

		rawTokens, err := lc.ExchangeAuthCode(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, rawTokens)

		tokens, err := lc.ProcessTokens(context.Background(), rawTokens)
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("unexpected audience", func(t *testing.T) {
		idp, lc := newLoginCallback(t, url, cookie)
		defer idp.Close()
		idp.ProviderHandler.Codes["some-code"] = mock.AuthorizeRequest{
			Nonce: "some-nonce",
		}
		idp.OpenIDConfig.ClientConfig.ClientID = "new-client-id"

		rawTokens, err := lc.ExchangeAuthCode(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, rawTokens)

		tokens, err := lc.ProcessTokens(context.Background(), rawTokens)
		assert.Error(t, err)
		assert.Nil(t, tokens)
	})
}

func newLoginCallback(t *testing.T, url string, cookie *openid.LoginCookie) (mock.IdentityProvider, client.LoginCallback) {
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	idp := mock.NewIdentityProvider(mock.Config())

	cfg := idp.OpenIDConfig
	cfg.ClientConfig.LogoutCallbackURI = LogoutCallbackURI
	cfg.ClientConfig.PostLogoutRedirectURI = PostLogoutRedirectURI
	cfg.ProviderConfig.EndSessionEndpoint = EndSessionEndpoint

	loginCallback, err := newTestClientWithConfig(cfg).LoginCallback(req, idp.Provider, cookie)
	assert.NoError(t, err)

	return idp, loginCallback
}
