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
	GetClientID() string
	GetClientJWK() jwk.Key
	GetPostLogoutRedirectURI() string
	GetCallbackURI() string
	GetLogoutCallbackURI() string
	GetScopes() scopes.Scopes
	GetACRValues() string
	GetUILocales() string
	GetWellKnownURL() string
	Print()
}

type openIDConfig struct {
	wonderwallconfig.OpenID
	clientJwk         jwk.Key
	callbackURI       string
	logoutCallbackURI string
}

func (in *openIDConfig) GetCallbackURI() string {
	return in.callbackURI
}

func (in *openIDConfig) GetClientID() string {
	return in.ClientID
}

func (in *openIDConfig) GetClientJWK() jwk.Key {
	return in.clientJwk
}

func (in *openIDConfig) GetLogoutCallbackURI() string {
	return in.logoutCallbackURI
}

func (in *openIDConfig) GetPostLogoutRedirectURI() string {
	return in.PostLogoutRedirectURI
}

func (in *openIDConfig) GetScopes() scopes.Scopes {
	return scopes.DefaultScopes().WithAdditional(in.Scopes...)
}

func (in *openIDConfig) GetACRValues() string {
	return in.ACRValues
}

func (in *openIDConfig) GetUILocales() string {
	return in.UILocales
}

func (in *openIDConfig) GetWellKnownURL() string {
	return in.WellKnownURL
}

func (in *openIDConfig) Print() {
	logger := log.WithField("logger", "openid.config.client")

	logger.Info("🤔 openid client configuration 🤔")
	logger.Infof("acr values: '%s'", in.GetACRValues())
	logger.Infof("client id: '%s'", in.GetClientID())
	logger.Infof("post-logout redirect uri: '%s'", in.GetPostLogoutRedirectURI())
	logger.Infof("callback uri: '%s'", in.GetCallbackURI())
	logger.Infof("logout callback uri: '%s'", in.GetLogoutCallbackURI())
	logger.Infof("scopes: '%s'", in.GetScopes())
	logger.Infof("ui locales: '%s'", in.GetUILocales())
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

	openIDConfig := &openIDConfig{
		OpenID:            cfg.OpenID,
		clientJwk:         clientJwk,
		callbackURI:       callbackURI,
		logoutCallbackURI: logoutCallbackURI,
	}

	var clientConfig Client
	switch cfg.OpenID.Provider {
	case wonderwallconfig.ProviderIDPorten:
		clientConfig = openIDConfig.IDPorten()
	case wonderwallconfig.ProviderAzure:
		clientConfig = openIDConfig.Azure()
	case "":
		return nil, fmt.Errorf("missing required config %s", wonderwallconfig.OpenIDProvider)
	default:
		clientConfig = openIDConfig
	}

	if len(clientConfig.GetClientID()) == 0 {
		return nil, fmt.Errorf("missing required config %s", wonderwallconfig.OpenIDClientID)
	}

	if len(clientConfig.GetWellKnownURL()) == 0 {
		return nil, fmt.Errorf("missing required config %s", wonderwallconfig.OpenIDWellKnownURL)
	}

	clientConfig.Print()
	return clientConfig, nil
}

type azure struct {
	*openIDConfig
}

func (in *openIDConfig) Azure() Client {
	return &azure{
		openIDConfig: in,
	}
}

func (in *azure) GetScopes() scopes.Scopes {
	return scopes.DefaultScopes().
		WithAzureScope(in.ClientID).
		WithAdditional(in.Scopes...)
}

type idporten struct {
	*openIDConfig
}

func (in *openIDConfig) IDPorten() Client {
	return &idporten{
		openIDConfig: in,
	}
}
