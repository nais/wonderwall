package mock

import (
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/nais/wonderwall/pkg/config"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type TestClientConfiguration struct {
	*config.Config
	clientJwk        jwk.Key
	clientJwkAlg     jwa.KeyAlgorithm
	trustedAudiences map[string]bool
}

var _ openidconfig.Client = (*TestClientConfiguration)(nil)

func (c *TestClientConfiguration) ACRValues() string {
	return c.OpenID.ACRValues
}

func (c *TestClientConfiguration) Audiences() map[string]bool {
	return c.trustedAudiences
}

func (c *TestClientConfiguration) AuthMethod() openidconfig.AuthMethod {
	return openidconfig.AuthMethodPrivateKeyJWT
}

func (c *TestClientConfiguration) ClientID() string {
	return c.OpenID.ClientID
}

func (c *TestClientConfiguration) ClientJWK() jwk.Key {
	return c.clientJwk
}

func (c *TestClientConfiguration) ClientJWKAlgorithm() jwa.KeyAlgorithm {
	return c.clientJwkAlg
}

func (c *TestClientConfiguration) ClientSecret() string {
	return c.OpenID.ClientSecret
}

func (c *TestClientConfiguration) DomainHint() string {
	return c.OpenID.DomainHint
}

func (c *TestClientConfiguration) NewClientAuthJWTType() bool {
	return c.OpenID.NewClientAuthJWTType
}

func (c *TestClientConfiguration) SetPostLogoutRedirectURI(uri string) {
	c.OpenID.PostLogoutRedirectURI = uri
}

func (c *TestClientConfiguration) PostLogoutRedirectURI() string {
	return c.OpenID.PostLogoutRedirectURI
}

func (c *TestClientConfiguration) ResourceIndicator() string {
	return c.OpenID.ResourceIndicator
}

func (c *TestClientConfiguration) Scopes() scopes.Scopes {
	return scopes.DefaultScopes().WithAdditional(c.OpenID.Scopes...)
}

func (c *TestClientConfiguration) UILocales() string {
	return c.OpenID.UILocales
}

func (c *TestClientConfiguration) WellKnownURL() string {
	return c.OpenID.WellKnownURL
}

func clientConfiguration(cfg *config.Config, key jwk.Key) *TestClientConfiguration {
	alg, ok := key.Algorithm()
	if !ok {
		panic("test client JWK is missing an algorithm")
	}

	return &TestClientConfiguration{
		Config:           cfg,
		clientJwk:        key,
		clientJwkAlg:     alg,
		trustedAudiences: cfg.OpenID.TrustedAudiences(),
	}
}
