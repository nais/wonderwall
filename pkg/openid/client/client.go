package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/server"
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
		Transport: server.DefaultTransport(),
	}

	return &Client{
		cfg:          cfg,
		httpClient:   httpClient,
		jwksProvider: jwksProvider,
		oauth2Config: oauth2Config,
	}
}

func (c *Client) Login(r *http.Request) (*Login, error) {
	login, err := NewLogin(c, r)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	return login, nil
}

func (c *Client) LoginCallback(r *http.Request, cookie *openid.LoginCookie) (*LoginCallback, error) {
	loginCallback, err := NewLoginCallback(c, r, cookie)
	if err != nil {
		return nil, fmt.Errorf("callback: %w", err)
	}

	return loginCallback, nil
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

func (c *Client) RefreshGrant(ctx context.Context, refreshToken string) (*openid.TokenResponse, error) {
	assertion, err := c.MakeAssertion(DefaultClientAssertionLifetime)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}

	v := url.Values{}
	v.Set(openid.GrantType, openid.RefreshTokenValue)
	v.Set(openid.RefreshToken, refreshToken)
	v.Set(openid.ClientID, c.cfg.Client().ClientID())
	v.Set(openid.ClientAssertion, assertion)
	v.Set(openid.ClientAssertionType, openid.ClientAssertionTypeJwtBearer)

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Provider().TokenEndpoint(), strings.NewReader(v.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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
		return nil, fmt.Errorf("%w: HTTP %d: %s: %s", ErrOpenIDClient, resp.StatusCode, errorResponse.Error, errorResponse.ErrorDescription)
	} else if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrOpenIDServer, resp.StatusCode, body)
	}

	var tokenResponse openid.TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("unmarshalling token response: %w", err)
	}

	return &tokenResponse, nil
}

func StateMismatchError(expectedState, actualState string) error {
	if len(actualState) <= 0 {
		return fmt.Errorf("missing state parameter in request (possible csrf)")
	}

	if expectedState != actualState {
		return fmt.Errorf("state parameter mismatch (possible csrf): expected %s, got %s", expectedState, actualState)
	}

	return nil
}
