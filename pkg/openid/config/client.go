package config

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"

	wonderwallconfig "github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type Client interface {
	ACRValues() string
	ClientID() string
	ClientJWK() jwk.Key
	PostLogoutRedirectURI() string
	ResourceIndicator() string
	Scopes() scopes.Scopes
	UILocales() string
	WellKnownURL() string

	Print()
}

type client struct {
	wonderwallconfig.OpenID
	clientJwk jwk.Key
}

func (in *client) ACRValues() string {
	return in.OpenID.ACRValues
}

func (in *client) ClientID() string {
	return in.OpenID.ClientID
}

func (in *client) ClientJWK() jwk.Key {
	return in.clientJwk
}

func (in *client) PostLogoutRedirectURI() string {
	return in.OpenID.PostLogoutRedirectURI
}

func (in *client) ResourceIndicator() string {
	return in.OpenID.ResourceIndicator
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

	c := &client{
		OpenID:    cfg.OpenID,
		clientJwk: clientJwk,
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

func (in *client) Azure() *azure {
	return &azure{
		client: in,
	}
}

func (in *azure) Scopes() scopes.Scopes {
	return scopes.DefaultScopes().
		WithAzureScope(in.OpenID.ClientID).
		WithOfflineAccess().
		WithAdditional(in.OpenID.Scopes...)
}

type idporten struct {
	*client
}

func (in *client) IDPorten() *idporten {
	return &idporten{
		client: in,
	}
}
