package mock

import (
	"time"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/ingress"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

const (
	Ingress = "http://wonderwall"
)

func Config() *config.Config {
	return &config.Config{
		EncryptionKey: `G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`, // 256 bits key
		Ingresses:     []string{Ingress},
		OpenID: config.OpenID{
			ACRValues:             "idporten-loa-high",
			ClientID:              "client-id",
			PostLogoutRedirectURI: "https://google.com",
			Provider:              "test",
			Scopes:                []string{"some-scope"},
			UILocales:             "nb",
		},
		Session: config.Session{
			MaxLifetime: time.Hour,
		},
	}
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

func Ingresses(cfg *config.Config) *ingress.Ingresses {
	parsed, err := ingress.ParseIngresses(cfg)
	if err != nil {
		panic(err)
	}

	return parsed
}
