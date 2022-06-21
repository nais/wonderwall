package openid

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
)

type Client interface {
	Config() config.Config
	Provider() Provider
	OAuth2Config() *oauth2.Config

	Login(r *http.Request) (Login, error)
	LoginCallback(r *http.Request) error
	Logout(r *http.Request) error
	LogoutCallback(r *http.Request) error

	AuthCodeGrant(ctx context.Context, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error)
	RefreshGrant(r *http.Request) error
}

type client struct {
	cfg          config.Config
	provider     Provider
	oauth2Config *oauth2.Config
}

func NewClient(cfg config.Config, provider Provider) Client {
	oauth2Config := &oauth2.Config{
		ClientID: provider.GetClientConfiguration().GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   provider.GetOpenIDConfiguration().AuthorizationEndpoint,
			TokenURL:  provider.GetOpenIDConfiguration().TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: provider.GetClientConfiguration().GetCallbackURI(),
		Scopes:      provider.GetClientConfiguration().GetScopes(),
	}

	return &client{
		cfg:          cfg,
		provider:     provider,
		oauth2Config: oauth2Config,
	}
}

func (c client) Config() config.Config {
	return c.cfg
}

func (c client) Provider() Provider {
	return c.provider
}

func (c client) OAuth2Config() *oauth2.Config {
	return c.oauth2Config
}

func (c client) Login(r *http.Request) (Login, error) {
	login, err := NewLogin(c, r)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	return login, nil
}

func (c client) LoginCallback(r *http.Request) error {
	//TODO implement me
	panic("implement me")
}

func (c client) Logout(r *http.Request) error {
	//TODO implement me
	panic("implement me")
}

func (c client) LogoutCallback(r *http.Request) error {
	//TODO implement me
	panic("implement me")
}

func (c client) AuthCodeGrant(ctx context.Context, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return c.oauth2Config.Exchange(ctx, code, opts...)
}

func (c client) RefreshGrant(r *http.Request) error {
	//TODO implement me
	panic("implement me")
}
