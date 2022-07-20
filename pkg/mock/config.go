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
			ACRValues:             "Level4",
			ClientID:              "client-id",
			PostLogoutRedirectURI: "https://google.com",
			Provider:              "test",
			Scopes:                []string{"some-scope"},
			UILocales:             "nb",
		},
		SessionMaxLifetime: time.Hour,
	}

	err := cfg.Validate()
	if err != nil {
		panic(err)
	}

	return cfg
}

type TestConfiguration struct {
	TestClient   *TestClientConfiguration
	TestProvider *TestProviderConfiguration
}

func (c *TestConfiguration) Client() openidconfig.Client {
	return c.TestClient
}

func (c *TestConfiguration) Provider() openidconfig.Provider {
	return c.TestProvider
}

func NewTestConfiguration(cfg *config.Config) *TestConfiguration {
	return &TestConfiguration{
		TestClient:   clientConfiguration(cfg),
		TestProvider: providerConfiguration(cfg),
	}
}
