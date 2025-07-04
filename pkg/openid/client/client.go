package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/internal/retry"
	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	urlpkg "github.com/nais/wonderwall/pkg/url"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

func init() {
	jwt.Settings(jwt.WithFlattenAudience(true))
}

var (
	ErrOpenIDClient = errors.New("client error")
	ErrOpenIDServer = errors.New("server error")
)

const (
	DefaultClientAssertionLifetime = 30 * time.Second
)

type JwksProvider interface {
	GetPublicJwkSet(ctx context.Context) (*jwk.Set, error)
	RefreshPublicJwkSet(ctx context.Context) (*jwk.Set, error)
}

type Client struct {
	cfg          openidconfig.Config
	httpClient   *http.Client
	jwksProvider JwksProvider
	oauth2Config *oauth2.Config
}

func NewClient(cfg openidconfig.Config, jwksProvider JwksProvider) *Client {
	oauth2Config := &oauth2.Config{
		ClientID: cfg.Client().ClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   cfg.Provider().AuthorizationEndpoint(),
			TokenURL:  cfg.Provider().TokenEndpoint(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
		Scopes: cfg.Client().Scopes(),
	}

	httpClient := &http.Client{
		Timeout:   time.Second * 10,
		Transport: httpinternal.Transport(),
	}

	return &Client{
		cfg:          cfg,
		httpClient:   httpClient,
		jwksProvider: jwksProvider,
		oauth2Config: oauth2Config,
	}
}

func (c *Client) Logout(r *http.Request) (*Logout, error) {
	logout, err := NewLogout(c, r)
	if err != nil {
		return nil, fmt.Errorf("logout: %w", err)
	}

	return logout, nil
}

func (c *Client) LogoutCallback(r *http.Request, cookie *openid.LogoutCookie, validator urlpkg.Validator) *LogoutCallback {
	return NewLogoutCallback(c, r, cookie, validator)
}

func (c *Client) AuthCodeGrant(ctx context.Context, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	return c.oauth2Config.Exchange(ctx, code, opts...)
}

func (c *Client) RefreshGrant(ctx context.Context, refreshToken, previousIDToken, expectedAcr string) (*openid.TokenResponse, error) {
	ctx, span := otel.StartSpan(ctx, "Client.RefreshGrant")
	defer span.End()
	clientAuth, err := c.ClientAuthenticationParams()
	if err != nil {
		return nil, err
	}

	endpoint := c.cfg.Provider().TokenEndpoint()
	payload := openid.RefreshGrantParams(c.cfg.Client().ClientID(), refreshToken).
		With(clientAuth)

	body, err := c.oauthPostRequest(ctx, endpoint, payload)
	if err != nil {
		return nil, err
	}

	var tokenResponse openid.TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("unmarshalling token response: %w", err)
	}
	span.SetAttributes(attribute.Int64("oauth.token_expires_in_seconds", tokenResponse.ExpiresIn))
	if tokenResponse.ExpiresIn <= 0 {
		return nil, fmt.Errorf("invalid token response: expires_in must be greater than 0, got %d", tokenResponse.ExpiresIn)
	}

	// id_tokens may not always be returned from a refresh grant (OpenID Connect Core 12.1)
	if tokenResponse.IDToken != "" {
		jwkSet, err := c.jwksProvider.GetPublicJwkSet(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting jwks: %w", err)
		}

		err = openid.ValidateRefreshedIDToken(c.cfg, previousIDToken, tokenResponse.IDToken, expectedAcr, jwkSet)
		if err != nil {
			span.SetAttributes(attribute.Bool("oauth.valid_id_token", false))
			otel.AddErrorEvent(span, "refreshGrantError", "invalidIDToken", err)
			if errors.Is(err, jws.VerificationError()) {
				// JWKS might not be up to date, so we'll want to force a refresh for the next attempt
				_, _ = c.jwksProvider.RefreshPublicJwkSet(ctx)
				return nil, retry.RetryableError(err)
			}
			return nil, fmt.Errorf("validating refreshed id token: %w", err)
		}
	}

	return &tokenResponse, nil
}

func (c *Client) ClientAuthenticationParams() (openid.RequestParams, error) {
	switch c.cfg.Client().AuthMethod() {
	case openidconfig.AuthMethodPrivateKeyJWT:
		assertion, err := c.MakeAssertion(DefaultClientAssertionLifetime)
		if err != nil {
			return nil, fmt.Errorf("creating client assertion: %w", err)
		}

		return openid.ClientAuthJwtBearerParams(assertion), nil

	case openidconfig.AuthMethodClientSecret:
		return openid.ClientAuthSecretParams(c.cfg.Client().ClientSecret()), nil
	}

	return nil, fmt.Errorf("unsupported client authentication method: %q", c.cfg.Client().AuthMethod())
}

func (c *Client) MakeAssertion(expiration time.Duration) (string, error) {
	clientCfg := c.cfg.Client()
	providerCfg := c.cfg.Provider()
	key := clientCfg.ClientJWK()

	iat := time.Now().Add(-5 * time.Second).Truncate(time.Second)
	exp := iat.Add(expiration)

	tok, err := jwt.NewBuilder().
		Issuer(clientCfg.ClientID()).
		Subject(clientCfg.ClientID()).
		Audience([]string{providerCfg.Issuer()}). // the aud claim is flattened to a single string value on serialization
		IssuedAt(iat).
		Expiration(exp).
		JwtID(uuid.New().String()).
		Build()
	if err != nil {
		return "", fmt.Errorf("building client assertion: %w", err)
	}

	alg, ok := key.Algorithm()
	if !ok {
		return "", fmt.Errorf("missing algorithm on client key")
	}

	encoded, err := jwt.Sign(tok, jwt.WithKey(alg, key))
	if err != nil {
		return "", fmt.Errorf("signing client assertion: %w", err)
	}

	return string(encoded), nil
}

func (c *Client) oauthPostRequest(ctx context.Context, endpoint string, payload openid.RequestParams) ([]byte, error) {
	span := trace.SpanFromContext(ctx)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload.URLValues().Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading server response: %w", err)
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		var errorResponse openid.TokenErrorResponse
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return nil, fmt.Errorf("%w: HTTP %d: unmarshalling error response: %+v", ErrOpenIDClient, resp.StatusCode, err)
		}
		otel.AddErrorEvent(span, "oauthClientError", errorResponse.Error, errors.New(errorResponse.ErrorDescription))
		return nil, fmt.Errorf("%w: HTTP %d: %s: %s", ErrOpenIDClient, resp.StatusCode, errorResponse.Error, errorResponse.ErrorDescription)
	} else if resp.StatusCode >= 500 {
		otel.AddErrorEvent(span, "oauthServerError", ErrOpenIDServer.Error(), errors.New(string(body)))
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrOpenIDServer, resp.StatusCode, body)
	}

	return body, nil
}
