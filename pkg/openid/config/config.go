package config

import (
	wonderwallconfig "github.com/nais/wonderwall/pkg/config"
)

type Config interface {
	Client() Client
	Provider() *Provider

	Ingress() string
	Loginstatus() wonderwallconfig.Loginstatus
}

type config struct {
	clientConfig   Client
	providerConfig *Provider
	ingress        string
	loginstatus    wonderwallconfig.Loginstatus
}

func (c config) Client() Client {
	return c.clientConfig
}

func (c config) Provider() *Provider {
	return c.providerConfig
}

func (c config) Ingress() string {
	return c.ingress
}

func (c config) Loginstatus() wonderwallconfig.Loginstatus {
	return c.loginstatus
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

	return config{
		clientConfig:   clientCfg,
		providerConfig: providerCfg,
		ingress:        cfg.Ingress,
		loginstatus:    cfg.Loginstatus,
	}, nil
}
