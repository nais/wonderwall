package config

import (
	"context"
	"fmt"

	wonderwallconfig "github.com/nais/wonderwall/pkg/config"
)

type Config interface {
	Client() Client
	Provider() Provider
}

type openidconfig struct {
	clientConfig   Client
	providerConfig Provider
}

func (c *openidconfig) Client() Client {
	return c.clientConfig
}

func (c *openidconfig) Provider() Provider {
	return c.providerConfig
}

func NewConfig(ctx context.Context, cfg *wonderwallconfig.Config) (Config, error) {
	clientCfg, err := NewClientConfig(cfg)
	if err != nil {
		return nil, err
	}

	providerCfg, err := NewProviderConfig(ctx, cfg, clientCfg.ClientJWKAlgorithm())
	if err != nil {
		return nil, err
	}

	if cfg.OpenID.DPoP {
		algorithm := clientCfg.ClientJWKAlgorithm()
		if !providerCfg.DPoPSigningAlgValuesSupported().Contains(algorithm.String()) {
			return nil, fmt.Errorf("%q requires provider DPoP support for algorithm %q", wonderwallconfig.OpenIDDPoP, algorithm.String())
		}
	}

	return &openidconfig{
		clientConfig:   clientCfg,
		providerConfig: providerCfg,
	}, nil
}
