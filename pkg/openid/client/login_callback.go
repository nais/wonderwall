package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/pkg/openid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var (
	ErrCallbackIdentityProvider = errors.New("callback: identity provider error")
	ErrCallbackInvalidCookie    = errors.New("callback: invalid cookie")
	ErrCallbackInvalidState     = errors.New("callback: invalid state")
	ErrCallbackInvalidIssuer    = errors.New("callback: invalid issuer")
	ErrCallbackRedeemTokens     = errors.New("callback: redeeming tokens")
)

func (c *Client) LoginCallback(r *http.Request, cookie *openid.LoginCookie) (*openid.Tokens, error) {
	span := trace.SpanFromContext(r.Context())
	if cookie == nil {
		return nil, fmt.Errorf("%w: %s", ErrCallbackInvalidCookie, "cookie is nil")
	}

	query := r.URL.Query()

	if oauthError := query.Get("error"); len(oauthError) > 0 {
		oauthErrorDescription := query.Get("error_description")
		span.SetAttributes(attribute.String("login.oauth_error", oauthError), attribute.String("login.oauth_error_description", oauthErrorDescription))
		return nil, fmt.Errorf("%w: %s: %s", ErrCallbackIdentityProvider, oauthError, oauthErrorDescription)
	}

	if err := openid.StateMismatchError(query, cookie.State); err != nil {
		span.SetAttributes(attribute.Bool("login.state_mismatch", true))
		return nil, fmt.Errorf("%w: %s", ErrCallbackInvalidState, err)
	}

	if err := c.authorizationServerIssuerIdentification(query.Get("iss")); err != nil {
		span.SetAttributes(attribute.Bool("login.issuer_mismatch", true))
		return nil, fmt.Errorf("%w: %s", ErrCallbackInvalidIssuer, err)
	}

	tokens, err := c.redeemTokens(r.Context(), query.Get("code"), cookie)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCallbackRedeemTokens, err)
	}

	return tokens, nil
}

// Verify iss parameter if provider supports RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
func (c *Client) authorizationServerIssuerIdentification(iss string) error {
	if !c.cfg.Provider().AuthorizationResponseIssParameterSupported() {
		return nil
	}

	if len(iss) == 0 {
		return fmt.Errorf("missing issuer parameter")
	}

	expectedIss := c.cfg.Provider().Issuer()
	if iss != expectedIss {
		return fmt.Errorf("issuer mismatch: expected %q, got %q", expectedIss, iss)
	}

	return nil
}

func (c *Client) redeemTokens(ctx context.Context, code string, cookie *openid.LoginCookie) (*openid.Tokens, error) {
	ctx, span := otel.StartSpan(ctx, "Client.RedeemTokens")
	defer span.End()
	clientAuth, err := c.ClientAuthenticationParams()
	if err != nil {
		return nil, err
	}

	payload := openid.ExchangeAuthorizationCodeParams(
		c.cfg.Client().ClientID(),
		code,
		cookie.CodeVerifier,
		cookie.RedirectURI,
	).With(clientAuth).AuthCodeOptions()

	rawTokens, err := c.AuthCodeGrant(ctx, code, payload)
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code for token: %w", err)
	}
	span.SetAttributes(attribute.Int64("oauth.token_expires_in_seconds", rawTokens.ExpiresIn))

	jwkSet, err := c.jwksProvider.GetPublicJwkSet(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting jwks: %w", err)
	}

	tokens, err := openid.NewTokens(rawTokens, jwkSet, c.cfg, cookie)
	if err != nil {
		// JWKS might not be up to date, so we'll want to force a refresh for the next attempt
		_, _ = c.jwksProvider.RefreshPublicJwkSet(ctx)
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}

	return tokens, nil
}
