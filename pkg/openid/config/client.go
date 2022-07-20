package config

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"

	wonderwallconfig "github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/scopes"
	"github.com/nais/wonderwall/pkg/router/paths"
)

type Client interface {
	ACRValues() string
	CallbackURI() string
	ClientID() string
	ClientJWK() jwk.Key
	LogoutCallbackURI() string
	PostLogoutRedirectURI() string
	Scopes() scopes.Scopes
	UILocales() string
	WellKnownURL() string

	Print()
}

type client struct {
	wonderwallconfig.OpenID
	clientJwk         jwk.Key
	callbackURI       string
	logoutCallbackURI string
}

func (in *client) ACRValues() string {
	return in.OpenID.ACRValues
}

func (in *client) CallbackURI() string {
	return in.callbackURI
}

func (in *client) ClientID() string {
	return in.OpenID.ClientID
}

func (in *client) ClientJWK() jwk.Key {
	return in.clientJwk
}

func (in *client) LogoutCallbackURI() string {
	return in.logoutCallbackURI
}

func (in *client) PostLogoutRedirectURI() string {
	return in.OpenID.PostLogoutRedirectURI
}

func (in *client) Scopes() scopes.Scopes {
	return scopes.DefaultScopes().WithAdditional(in.OpenID.Scopes...)
}

func (in *client) UILocales() string {
	return in.OpenID.UILocales
}

func (in *client) WellKnownURL() string {
	return in.OpenID.WellKnownURL
}

func (in *client) Print() {
	logger := log.WithField("logger", "openid.config.client")

	logger.Info("🤔 openid client configuration 🤔")
	logger.Infof("acr values: '%s'", in.ACRValues())
	logger.Infof("client id: '%s'", in.ClientID())
	logger.Infof("post-logout redirect uri: '%s'", in.PostLogoutRedirectURI())
	logger.Infof("callback uri: '%s'", in.CallbackURI())
	logger.Infof("logout callback uri: '%s'", in.LogoutCallbackURI())
	logger.Infof("scopes: '%s'", in.Scopes())
	logger.Infof("ui locales: '%s'", in.UILocales())
}

func NewClientConfig(cfg *wonderwallconfig.Config) (Client, error) {
	clientJwkString := cfg.OpenID.ClientJWK
	if len(clientJwkString) == 0 {
		return nil, fmt.Errorf("missing required config %s", wonderwallconfig.OpenIDClientJWK)
	}

	clientJwk, err := jwk.ParseKey([]byte(clientJwkString))
	if err != nil {
		return nil, fmt.Errorf("parsing client JWK: %w", err)
	}

	ingress := cfg.Ingress
	if len(ingress) == 0 {
		return nil, fmt.Errorf("missing required config %s", wonderwallconfig.Ingress)
	}

	callbackURI, err := RedirectURI(ingress, paths.Callback)
	if err != nil {
		return nil, fmt.Errorf("creating callback URI from ingress: %w", err)
	}

	logoutCallbackURI, err := RedirectURI(ingress, paths.LogoutCallback)
	if err != nil {
		return nil, fmt.Errorf("creating logout callback URI from ingress: %w", err)
	}

	c := &client{
		OpenID:            cfg.OpenID,
		clientJwk:         clientJwk,
		callbackURI:       callbackURI,
		logoutCallbackURI: logoutCallbackURI,
	}

	var clientConfig Client
	switch cfg.OpenID.Provider {
	case wonderwallconfig.ProviderIDPorten:
		clientConfig = c.IDPorten()
	case wonderwallconfig.ProviderAzure:
		clientConfig = c.Azure()
	case "":
		return nil, fmt.Errorf("missing required config %s", wonderwallconfig.OpenIDProvider)
	default:
		clientConfig = c
	}

	if len(clientConfig.ClientID()) == 0 {
		return nil, fmt.Errorf("missing required config %s", wonderwallconfig.OpenIDClientID)
	}

	if len(clientConfig.WellKnownURL()) == 0 {
		return nil, fmt.Errorf("missing required config %s", wonderwallconfig.OpenIDWellKnownURL)
	}

	clientConfig.Print()
	return clientConfig, nil
}

type azure struct {
	*client
}

func (in *client) Azure() Client {
	return &azure{
		client: in,
	}
}

func (in *azure) Scopes() scopes.Scopes {
	return scopes.DefaultScopes().
		WithAzureScope(in.OpenID.ClientID).
		WithAdditional(in.OpenID.Scopes...)
}

type idporten struct {
	*client
}

func (in *client) IDPorten() Client {
	return &idporten{
		client: in,
	}
}
