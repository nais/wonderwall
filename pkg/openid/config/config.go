package config

import (
	wonderwallconfig "github.com/nais/wonderwall/pkg/config"
)

type Config interface {
	Client() Client
	Provider() *Provider
	ProviderName() string

	Wonderwall() *wonderwallconfig.Config
}

type config struct {
	cfg            *wonderwallconfig.Config
	clientConfig   Client
	providerConfig *Provider
}

func (c *config) Client() Client {
	return c.clientConfig
}

func (c *config) Provider() *Provider {
	return c.providerConfig
}

func (c *config) ProviderName() string {
	return string(c.cfg.OpenID.Provider)
}

func (c *config) Wonderwall() *wonderwallconfig.Config {
	return c.cfg
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

	return &config{
		cfg:            cfg,
		clientConfig:   clientCfg,
		providerConfig: providerCfg,
	}, nil
}
