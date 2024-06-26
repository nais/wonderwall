package config

import (
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

func NewConfig(cfg *wonderwallconfig.Config) (Config, error) {
	clientCfg, err := NewClientConfig(cfg)
	if err != nil {
		return nil, err
	}

	providerCfg, err := NewProviderConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &openidconfig{
		clientConfig:   clientCfg,
		providerConfig: providerCfg,
	}, nil
}
