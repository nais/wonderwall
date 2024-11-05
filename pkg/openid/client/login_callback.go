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
	cookie *openid.LoginCookie
	query  url.Values
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
		Client: c,
		cookie: cookie,
		query:  r.URL.Query(),
	}, nil
}

func (in *LoginCallback) IdentityProviderError() error {
	if in.query.Get("error") != "" {
		oauthError := in.query.Get("error")
		oauthErrorDescription := in.query.Get("error_description")
		return fmt.Errorf("error from identity provider: %s: %s", oauthError, oauthErrorDescription)
	}

	return nil
}

func (in *LoginCallback) StateMismatchError() error {
	return openid.StateMismatchError(in.query, in.cookie.State)
}

func (in *LoginCallback) RedeemTokens(ctx context.Context) (*openid.Tokens, error) {
	params, err := in.AuthParams()
	if err != nil {
		return nil, err
	}

	rawTokens, err := in.AuthCodeGrant(ctx, in.query.Get("code"), params.AuthCodeOptions([]oauth2.AuthCodeOption{
		openid.RedirectURIOption(in.cookie.RedirectURI),
		oauth2.VerifierOption(in.cookie.CodeVerifier),
	}))
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code for token: %w", err)
	}

	jwkSet, err := in.jwksProvider.GetPublicJwkSet(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting jwks: %w", err)
	}

	tokens, err := openid.NewTokens(rawTokens, jwkSet, in.cfg, in.cookie)
	if err != nil {
		// JWKS might not be up to date, so we'll want to force a refresh for the next attempt
		_, _ = in.jwksProvider.RefreshPublicJwkSet(ctx)
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}

	return tokens, nil
}
