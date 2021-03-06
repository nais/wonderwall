package client

import (
	"context"
	"fmt"
	"net/http"
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

	Login(r *http.Request, ingress string, loginstatus loginstatus.Loginstatus) (Login, error)
	LoginCallback(r *http.Request, p provider.Provider, cookie *openid.LoginCookie) (LoginCallback, error)
	Logout() Logout
	LogoutCallback(r *http.Request, ingress string) LogoutCallback
	LogoutFrontchannel(r *http.Request) LogoutFrontchannel

	AuthCodeGrant(ctx context.Context, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error)
	MakeAssertion(expiration time.Duration) (string, error)
	RefreshGrant(r *http.Request) error
}

type client struct {
	cfg          openidconfig.Config
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
		RedirectURL: cfg.Client().CallbackURI(),
		Scopes:      cfg.Client().Scopes(),
	}

	return &client{
		cfg:          cfg,
		oauth2Config: oauth2Config,
	}
}

func (c *client) config() openidconfig.Config {
	return c.cfg
}

func (c *client) oAuth2Config() *oauth2.Config {
	return c.oauth2Config
}

func (c *client) Login(r *http.Request, ingress string, loginstatus loginstatus.Loginstatus) (Login, error) {
	login, err := NewLogin(c, r, ingress, loginstatus)
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

func (c *client) Logout() Logout {
	return NewLogout(c)
}

func (c *client) LogoutCallback(r *http.Request, ingress string) LogoutCallback {
	return NewLogoutCallback(c, r, ingress)
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

func (c *client) RefreshGrant(r *http.Request) error {
	//TODO implement me
	panic("implement me")
}
