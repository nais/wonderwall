package openid

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/clients"
)

type Provider interface {
	GetClientConfiguration() clients.Configuration
	GetOpenIDConfiguration() *Configuration
	GetPublicJwkSet() *jwk.Set
}

type provider struct {
	clientConfiguration clients.Configuration
	configuration       *Configuration
	jwkSet              *jwk.Set
}

func (p provider) GetClientConfiguration() clients.Configuration {
	return p.clientConfiguration
}

func (p provider) GetOpenIDConfiguration() *Configuration {
	return p.configuration
}

func (p provider) GetPublicJwkSet() *jwk.Set {
	return p.jwkSet
}

func NewProvider(cfg *config.Config) (Provider, error) {
	clientJwkString := cfg.OpenID.ClientJWK
	if len(clientJwkString) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.OpenIDClientJWK)
	}

	clientJwk, err := jwk.ParseKey([]byte(clientJwkString))
	if err != nil {
		return nil, fmt.Errorf("parsing client JWK: %w", err)
	}

	ingress := cfg.Ingress
	if len(ingress) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.Ingress)
	}

	redirectURI, err := RedirectURI(ingress)
	if err != nil {
		return nil, fmt.Errorf("creating redirect URI from ingress: %w", err)
	}

	baseConfig := clients.NewBaseConfig(*cfg, clientJwk, redirectURI)
	var clientConfig clients.Configuration
	switch cfg.OpenID.Provider {
	case config.ProviderIDPorten:
		clientConfig = baseConfig.IDPorten()
	case config.ProviderAzure:
		clientConfig = baseConfig.Azure()
	case "":
		return nil, fmt.Errorf("missing required config %s", config.OpenIDProvider)
	default:
		clientConfig = baseConfig
	}

	if len(clientConfig.GetClientID()) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.OpenIDClientID)
	}

	if len(clientConfig.GetWellKnownURL()) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.OpenIDWellKnownURL)
	}

	configuration, err := FetchWellKnownConfig(clientConfig.GetWellKnownURL())
	if err != nil {
		return nil, fmt.Errorf("fetching well known config: %w", err)
	}

	printConfigs(clientConfig, *configuration)

	acrValues := clientConfig.GetACRValues()
	if len(acrValues) > 0 && !configuration.ACRValuesSupported.Contains(acrValues) {
		return nil, fmt.Errorf("identity provider does not support '%s=%s'", config.OpenIDACRValues, acrValues)
	}

	uiLocales := clientConfig.GetUILocales()
	if len(uiLocales) > 0 && !configuration.UILocalesSupported.Contains(uiLocales) {
		return nil, fmt.Errorf("identity provider does not support '%s=%s'", config.OpenIDUILocales, acrValues)
	}

	jwkSet, err := configuration.FetchJwkSet(context.Background())
	if err != nil {
		return nil, fmt.Errorf("fetching jwk set: %w", err)
	}

	return &provider{
		clientConfiguration: clientConfig,
		configuration:       configuration,
		jwkSet:              jwkSet,
	}, nil
}

func printConfigs(clientCfg clients.Configuration, openIdCfg Configuration) {
	log.Info("🤔 openid client configuration 🤔")
	log.Infof("acr values: '%s'", clientCfg.GetACRValues())
	log.Infof("client id: '%s'", clientCfg.GetClientID())
	log.Infof("post-logout redirect uri: '%s'", clientCfg.GetPostLogoutRedirectURI())
	log.Infof("redirect uri: '%s'", clientCfg.GetRedirectURI())
	log.Infof("scopes: '%s'", clientCfg.GetScopes())
	log.Infof("ui locales: '%s'", clientCfg.GetUILocales())

	log.Info("😗 openid provider configuration 😗")
	log.Infof("%#v", openIdCfg)
}
