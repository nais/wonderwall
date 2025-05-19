package mock

import (
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/config"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type TestClientConfiguration struct {
	*config.Config
	clientJwk        jwk.Key
	trustedAudiences map[string]bool
}

func (c *TestClientConfiguration) ACRValues() string {
	return c.Config.OpenID.ACRValues
}

func (c *TestClientConfiguration) Audiences() map[string]bool {
	return c.trustedAudiences
}

func (c *TestClientConfiguration) AuthMethod() openidconfig.AuthMethod {
	return openidconfig.AuthMethodPrivateKeyJWT
}

func (c *TestClientConfiguration) ClientID() string {
	return c.Config.OpenID.ClientID
}

func (c *TestClientConfiguration) ClientJWK() jwk.Key {
	return c.clientJwk
}

func (c *TestClientConfiguration) ClientSecret() string {
	return c.Config.OpenID.ClientSecret
}

func (c *TestClientConfiguration) SetPostLogoutRedirectURI(uri string) {
	c.Config.OpenID.PostLogoutRedirectURI = uri
}

func (c *TestClientConfiguration) PostLogoutRedirectURI() string {
	return c.Config.OpenID.PostLogoutRedirectURI
}

func (c *TestClientConfiguration) ResourceIndicator() string {
	return c.Config.OpenID.ResourceIndicator
}

func (c *TestClientConfiguration) Scopes() scopes.Scopes {
	return scopes.DefaultScopes().WithAdditional(c.Config.OpenID.Scopes...)
}

func (c *TestClientConfiguration) UILocales() string {
	return c.Config.OpenID.UILocales
}

func (c *TestClientConfiguration) WellKnownURL() string {
	return c.Config.OpenID.WellKnownURL
}

func clientConfiguration(cfg *config.Config) *TestClientConfiguration {
	key, err := crypto.NewJwk()
	if err != nil {
		panic(err)
	}

	return &TestClientConfiguration{
		Config:           cfg,
		clientJwk:        key,
		trustedAudiences: cfg.OpenID.TrustedAudiences(),
	}
}
