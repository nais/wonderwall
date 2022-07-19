package mock

import (
	"time"

	"github.com/nais/wonderwall/pkg/config"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func Config() *config.Config {
	cfg := &config.Config{
		EncryptionKey: `G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`, // 256 bits AES
		Ingress:       "/",
		OpenID: config.OpenID{
			Provider: "test",
			ClientID: "client-id",
			Scopes:   []string{"some-scope"},
		},
		SessionMaxLifetime: time.Hour,
	}

	err := cfg.Validate()
	if err != nil {
		panic(err)
	}

	return cfg
}

type Configuration struct {
	ClientConfig     *TestClientConfiguration
	ProviderConfig   *openidconfig.Provider
	WonderwallConfig *config.Config
}

func (c *Configuration) Client() openidconfig.Client {
	return c.ClientConfig
}

func (c *Configuration) Provider() *openidconfig.Provider {
	return c.ProviderConfig
}

func (c *Configuration) ProviderName() string {
	return string(c.WonderwallConfig.OpenID.Provider)
}

func (c *Configuration) Wonderwall() *config.Config {
	return c.WonderwallConfig
}

func NewTestConfiguration(cfg *config.Config) *Configuration {
	return &Configuration{
		ClientConfig:     clientConfiguration(cfg),
		ProviderConfig:   providerConfiguration(),
		WonderwallConfig: cfg,
	}
}
