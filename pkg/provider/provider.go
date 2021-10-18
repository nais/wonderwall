package provider

import (
	"context"
	"fmt"
	"net/url"
	"path"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/paths"
)

type Provider interface {
	GetClientConfiguration() openid.ClientConfiguration
	GetOpenIDConfiguration() *openid.Configuration
	GetPublicJwkSet() *jwk.Set
}

type provider struct {
	clientConfiguration openid.ClientConfiguration
	configuration       *openid.Configuration
	jwkSet              *jwk.Set
}

func (p provider) GetClientConfiguration() openid.ClientConfiguration {
	return p.clientConfiguration
}

func (p provider) GetOpenIDConfiguration() *openid.Configuration {
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

	baseConfig := cfg.NewBaseConfig(clientJwk, redirectURI)
	var clientConfig openid.ClientConfiguration
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

	configuration, err := openid.FetchWellKnownConfig(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("fetching well known config: %w", err)
	}

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

func RedirectURI(ingress string) (string, error) {
	if len(ingress) == 0 {
		return "", fmt.Errorf("ingress cannot be empty")
	}

	base, err := url.Parse(ingress)
	if err != nil {
		return "", err
	}

	base.Path = path.Join(base.Path, paths.OAuth2, paths.Callback)
	return base.String(), nil
}
