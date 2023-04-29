package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/openid"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

type LoginCallback struct {
	*Client
	cookie        *openid.LoginCookie
	request       *http.Request
	requestParams url.Values
}

func NewLoginCallback(c *Client, r *http.Request, cookie *openid.LoginCookie) (*LoginCallback, error) {
	if cookie == nil {
		return nil, fmt.Errorf("cookie is nil")
	}

	// redirect_uri not set in cookie (e.g. login initiated at instance running older version, callback handled at newer version)
	if len(cookie.RedirectURI) == 0 {
		callbackURL, err := urlpkg.LoginCallback(r)
		if err != nil {
			return nil, fmt.Errorf("generating callback url: %w", err)
		}

		cookie.RedirectURI = callbackURL
	}

	return &LoginCallback{
		Client:        c,
		cookie:        cookie,
		request:       r,
		requestParams: r.URL.Query(),
	}, nil
}

func (in *LoginCallback) IdentityProviderError() error {
	if in.requestParams.Get(openid.Error) != "" {
		oauthError := in.requestParams.Get(openid.Error)
		oauthErrorDescription := in.requestParams.Get(openid.ErrorDescription)
		return fmt.Errorf("error from identity provider: %s: %s", oauthError, oauthErrorDescription)
	}

	return nil
}

func (in *LoginCallback) StateMismatchError() error {
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

func (in *LoginCallback) RedeemTokens(ctx context.Context) (*openid.Tokens, error) {
	clientAssertion, err := in.MakeAssertion(DefaultClientAssertionLifetime)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam(openid.CodeVerifier, in.cookie.CodeVerifier),
		oauth2.SetAuthURLParam(openid.ClientAssertion, clientAssertion),
		oauth2.SetAuthURLParam(openid.ClientAssertionType, openid.ClientAssertionTypeJwtBearer),
		oauth2.SetAuthURLParam(openid.RedirectURI, in.cookie.RedirectURI),
	}

	code := in.requestParams.Get(openid.Code)
	rawTokens, err := in.AuthCodeGrant(ctx, code, opts)
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code for token: %w", err)
	}

	jwkSet, err := in.jwksProvider.GetPublicJwkSet(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting jwks: %w", err)
	}

	tokens, err := openid.NewTokens(rawTokens, *jwkSet)
	if err != nil {
		// JWKS might not be up-to-date, so we'll want to force a refresh for the next attempt
		_, _ = in.jwksProvider.RefreshPublicJwkSet(ctx)
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}

	err = tokens.IDToken.Validate(in.cfg, in.cookie)
	if err != nil {
		return nil, fmt.Errorf("validating id_token: %w", err)
	}

	return tokens, nil
}
