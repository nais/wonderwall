package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/provider"
)

const (
	ClientAssertionTypeJwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type LoginCallback interface {
	IdentityProviderError() error
	StateMismatchError() error
	RedeemTokens(ctx context.Context) (*openid.Tokens, error)
}

type loginCallback struct {
	client        Client
	cookie        *openid.LoginCookie
	provider      provider.Provider
	request       *http.Request
	requestParams url.Values
}

func NewLoginCallback(c Client, r *http.Request, p provider.Provider, cookie *openid.LoginCookie) (LoginCallback, error) {
	if cookie == nil {
		return nil, fmt.Errorf("cookie is nil")
	}

	return &loginCallback{
		client:        c,
		cookie:        cookie,
		provider:      p,
		request:       r,
		requestParams: r.URL.Query(),
	}, nil
}

func (in *loginCallback) IdentityProviderError() error {
	if in.requestParams.Get(openid.Error) != "" {
		oauthError := in.requestParams.Get(openid.Error)
		oauthErrorDescription := in.requestParams.Get(openid.ErrorDescription)
		return fmt.Errorf("error from identity provider: %s: %s", oauthError, oauthErrorDescription)
	}

	return nil
}

func (in *loginCallback) StateMismatchError() error {
	expectedState := in.cookie.State
	actualState := in.requestParams.Get(openid.State)

	if len(actualState) <= 0 {
		return fmt.Errorf("missing state parameter in request (possible csrf)")
	}

	if expectedState != actualState {
		return fmt.Errorf("state parameter mismatch (possible csrf): expected %s, got %s", expectedState, actualState)
	}

	return nil
}

func (in *loginCallback) RedeemTokens(ctx context.Context) (*openid.Tokens, error) {
	clientAssertion, err := in.client.MakeAssertion(time.Second * 30)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam(openid.CodeVerifier, in.cookie.CodeVerifier),
		oauth2.SetAuthURLParam(openid.ClientAssertion, clientAssertion),
		oauth2.SetAuthURLParam(openid.ClientAssertionType, ClientAssertionTypeJwtBearer),
		oauth2.SetAuthURLParam(openid.RedirectURI, in.cookie.RedirectURI),
	}

	code := in.requestParams.Get(openid.Code)
	rawTokens, err := in.client.AuthCodeGrant(ctx, code, opts)
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code for token: %w", err)
	}

	jwkSet, err := in.provider.GetPublicJwkSet(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting jwks: %w", err)
	}

	tokens, err := openid.NewTokens(rawTokens, *jwkSet)
	if err != nil {
		// JWKS might not be up-to-date, so we'll want to force a refresh for the next attempt
		_, _ = in.provider.RefreshPublicJwkSet(ctx)
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}

	err = tokens.IDToken.Validate(in.client.config(), in.cookie.Nonce)
	if err != nil {
		return nil, fmt.Errorf("validating id_token: %w", err)
	}

	return tokens, nil
}
