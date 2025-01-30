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

	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

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

func (c *Client) LogoutFrontchannel(r *http.Request) *LogoutFrontchannel {
	return NewLogoutFrontchannel(r)
}

func (c *Client) AuthCodeGrant(ctx context.Context, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	return c.oauth2Config.Exchange(ctx, code, opts...)
}

func (c *Client) RefreshGrant(ctx context.Context, refreshToken string) (*openid.TokenResponse, error) {
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

	errs := make([]error, 0)

	tok := jwt.New()
	errs = append(errs, tok.Set(jwt.IssuerKey, clientCfg.ClientID()))
	errs = append(errs, tok.Set(jwt.SubjectKey, clientCfg.ClientID()))
	errs = append(errs, tok.Set(jwt.AudienceKey, providerCfg.Issuer()))
	errs = append(errs, tok.Set(jwt.IssuedAtKey, iat))
	errs = append(errs, tok.Set(jwt.ExpirationKey, exp))
	errs = append(errs, tok.Set(jwt.JwtIDKey, uuid.New().String()))

	for _, err := range errs {
		if err != nil {
			return "", fmt.Errorf("setting claim for client assertion: %w", err)
		}
	}

	encoded, err := jwt.Sign(tok, jwt.WithKey(key.Algorithm(), key))
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
