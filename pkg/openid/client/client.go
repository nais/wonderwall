package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/provider"
)

type Client interface {
	config() openidconfig.Config
	oAuth2Config() *oauth2.Config

	Login(r *http.Request) (Login, error)
	LoginCallback(r *http.Request, p provider.Provider, cookie *openid.LoginCookie) LoginCallback
	Logout() (Logout, error)
	LogoutCallback(r *http.Request, cookie *openid.LogoutCookie) LogoutCallback
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
		ClientID: cfg.Client().GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   cfg.Provider().AuthorizationEndpoint,
			TokenURL:  cfg.Provider().TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: cfg.Client().GetCallbackURI(),
		Scopes:      cfg.Client().GetScopes(),
	}

	return &client{
		cfg:          cfg,
		oauth2Config: oauth2Config,
	}
}

func (c client) config() openidconfig.Config {
	return c.cfg
}

func (c client) oAuth2Config() *oauth2.Config {
	return c.oauth2Config
}

func (c client) Login(r *http.Request) (Login, error) {
	login, err := NewLogin(c, r)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	return login, nil
}

func (c client) LoginCallback(r *http.Request, p provider.Provider, cookie *openid.LoginCookie) LoginCallback {
	return NewLoginCallback(c, r, p, cookie)
}

func (c client) Logout() (Logout, error) {
	logout, err := NewLogout(c)
	if err != nil {
		return nil, fmt.Errorf("logout: %w", err)
	}

	return logout, nil
}

func (c client) LogoutCallback(r *http.Request, cookie *openid.LogoutCookie) LogoutCallback {
	return NewLogoutCallback(r, cookie)
}

func (c client) LogoutFrontchannel(r *http.Request) LogoutFrontchannel {
	return NewLogoutFrontchannel(r)
}

func (c client) AuthCodeGrant(ctx context.Context, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return c.oauth2Config.Exchange(ctx, code, opts...)
}

func (c client) MakeAssertion(expiration time.Duration) (string, error) {
	clientCfg := c.config().Client()
	providerCfg := c.config().Provider()
	key := clientCfg.GetClientJWK()

	iat := time.Now()
	exp := iat.Add(expiration)

	errs := make([]error, 0)

	tok := jwt.New()
	errs = append(errs, tok.Set(jwt.IssuerKey, clientCfg.GetClientID()))
	errs = append(errs, tok.Set(jwt.SubjectKey, clientCfg.GetClientID()))
	errs = append(errs, tok.Set(jwt.AudienceKey, providerCfg.Issuer))
	errs = append(errs, tok.Set("scope", clientCfg.GetScopes().String()))
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

func (c client) RefreshGrant(r *http.Request) error {
	//TODO implement me
	panic("implement me")
}
