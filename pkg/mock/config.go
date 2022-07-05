package mock

import (
	"time"

	"github.com/nais/wonderwall/pkg/config"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func Config() *config.Config {
	return &config.Config{
		EncryptionKey: `G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`, // 256 bits AES
		Ingress:       "/",
		OpenID: config.OpenID{
			Provider: "test",
			ClientID: "client-id",
		},
		SessionMaxLifetime: time.Hour,
	}
}

type Configuration struct {
	ClientConfig      *TestClientConfiguration
	ProviderConfig    *openidconfig.Provider
	IngressConfig     string
	LoginstatusConfig config.Loginstatus
}

func (c Configuration) Client() openidconfig.Client {
	return c.ClientConfig
}

func (c Configuration) Provider() *openidconfig.Provider {
	return c.ProviderConfig
}

func (c Configuration) Ingress() string {
	return c.IngressConfig
}

func (c Configuration) Loginstatus() config.Loginstatus {
	return c.LoginstatusConfig
}

func NewTestConfiguration(cfg *config.Config) Configuration {
	return Configuration{
		ClientConfig:      clientConfiguration(cfg),
		ProviderConfig:    providerConfiguration(),
		IngressConfig:     cfg.Ingress,
		LoginstatusConfig: cfg.Loginstatus,
	}
}
