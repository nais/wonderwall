package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/provider"
)

type Client interface {
	config() openidconfig.Config
	oAuth2Config() *oauth2.Config

	SetHttpClient(c *http.Client)

	Login(r *http.Request, loginstatus loginstatus.Loginstatus) (Login, error)
	LoginCallback(r *http.Request, p provider.Provider, cookie *openid.LoginCookie) (LoginCallback, error)
	Logout(r *http.Request) (Logout, error)
	LogoutCallback(r *http.Request) LogoutCallback
	LogoutFrontchannel(r *http.Request) LogoutFrontchannel

	AuthCodeGrant(ctx context.Context, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error)
	MakeAssertion(expiration time.Duration) (string, error)
	RefreshGrant(ctx context.Context, refreshToken string) (*openid.TokenResponse, error)
}

type client struct {
	cfg          openidconfig.Config
	httpClient   *http.Client
	oauth2Config *oauth2.Config
}

func NewClient(cfg openidconfig.Config) Client {
	oauth2Config := &oauth2.Config{
		ClientID: cfg.Client().ClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   cfg.Provider().AuthorizationEndpoint(),
			TokenURL:  cfg.Provider().TokenEndpoint(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
		Scopes: cfg.Client().Scopes(),
	}

	return &client{
		cfg:          cfg,
		httpClient:   http.DefaultClient,
		oauth2Config: oauth2Config,
	}
}

func (c *client) config() openidconfig.Config {
	return c.cfg
}

func (c *client) oAuth2Config() *oauth2.Config {
	return c.oauth2Config
}

func (c *client) SetHttpClient(httpClient *http.Client) {
	c.httpClient = httpClient
}

func (c *client) Login(r *http.Request, loginstatus loginstatus.Loginstatus) (Login, error) {
	login, err := NewLogin(c, r, loginstatus)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	return login, nil
}

func (c *client) LoginCallback(r *http.Request, p provider.Provider, cookie *openid.LoginCookie) (LoginCallback, error) {
	loginCallback, err := NewLoginCallback(c, r, p, cookie)
	if err != nil {
		return nil, fmt.Errorf("callback: %w", err)
	}

	return loginCallback, nil
}

func (c *client) Logout(r *http.Request) (Logout, error) {
	logout, err := NewLogout(c, r)
	if err != nil {
		return nil, fmt.Errorf("logout: %w", err)
	}

	return logout, nil
}

func (c *client) LogoutCallback(r *http.Request) LogoutCallback {
	return NewLogoutCallback(c, r)
}

func (c *client) LogoutFrontchannel(r *http.Request) LogoutFrontchannel {
	return NewLogoutFrontchannel(r)
}

func (c *client) AuthCodeGrant(ctx context.Context, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return c.oauth2Config.Exchange(ctx, code, opts...)
}

func (c *client) MakeAssertion(expiration time.Duration) (string, error) {
	clientCfg := c.config().Client()
	providerCfg := c.config().Provider()
	key := clientCfg.ClientJWK()

	iat := time.Now().Truncate(time.Second)
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

func (c *client) RefreshGrant(ctx context.Context, refreshToken string) (*openid.TokenResponse, error) {
	assertion, err := c.MakeAssertion(30 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}

	v := url.Values{}
	v.Set(openid.GrantType, openid.RefreshTokenValue)
	v.Set(openid.RefreshToken, refreshToken)
	v.Set(openid.ClientID, c.config().Client().ClientID())
	v.Set(openid.ClientAssertion, assertion)
	v.Set(openid.ClientAssertionType, openid.ClientAssertionTypeJwtBearer)

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config().Provider().TokenEndpoint(), strings.NewReader(v.Encode()))
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
			return nil, fmt.Errorf("client error: HTTP %d: unmarshalling error response: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("client error: HTTP %d: %s: %s", resp.StatusCode, errorResponse.Error, errorResponse.ErrorDescription)
	} else if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("server error: HTTP %d: %s", resp.StatusCode, body)
	}

	var tokenResponse openid.TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("unmarshalling token response: %w", err)
	}

	return &tokenResponse, nil
}
