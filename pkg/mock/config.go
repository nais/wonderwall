package mock

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/nais/wonderwall/internal/crypto"
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
			JWKSFallbackAlg:       "RS256",
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
	key, err := crypto.NewJwk()
	if err != nil {
		panic(err)
	}

	return NewTestConfigurationWithClientJWK(cfg, key)
}

func NewTestConfigurationWithClientJWK(cfg *config.Config, key jwk.Key) *TestConfiguration {
	return &TestConfiguration{
		TestClient:   clientConfiguration(cfg, key),
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
