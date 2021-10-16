package provider

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid"
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

	baseConfig := cfg.NewBaseConfig(clientJwk)
	var clientConfig openid.ClientConfiguration
	switch cfg.OpenID.Provider {
	case "idporten":
		clientConfig = baseConfig.IDPorten()
	case "azure":
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

	if len(clientConfig.GetRedirectURI()) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.OpenIDRedirectURI)
	}

	configuration, err := openid.FetchWellKnownConfig(clientConfig.GetWellKnownURL())
	if err != nil {
		return nil, fmt.Errorf("fetching well known config: %w", err)
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
