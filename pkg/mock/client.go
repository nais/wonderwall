package mock

import (
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type TestClientConfiguration struct {
	*config.Config
	callbackURI       string
	clientJwk         jwk.Key
	logoutCallbackURI string
}

func (c *TestClientConfiguration) ACRValues() string {
	return c.Config.OpenID.ACRValues
}

func (c *TestClientConfiguration) CallbackURI() string {
	return c.callbackURI
}

func (c *TestClientConfiguration) ClientID() string {
	return c.Config.OpenID.ClientID
}

func (c *TestClientConfiguration) ClientJWK() jwk.Key {
	return c.clientJwk
}

func (c *TestClientConfiguration) LogoutCallbackURI() string {
	return c.logoutCallbackURI
}

func (c *TestClientConfiguration) PostLogoutRedirectURI() string {
	return c.Config.OpenID.PostLogoutRedirectURI
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

func (c *TestClientConfiguration) Print() {}

func (c *TestClientConfiguration) SetLogoutCallbackURI(url string) {
	c.logoutCallbackURI = url
}

func clientConfiguration(cfg *config.Config) *TestClientConfiguration {
	key, err := crypto.NewJwk()
	if err != nil {
		panic(err)
	}

	return &TestClientConfiguration{
		Config:            cfg,
		clientJwk:         key,
		callbackURI:       "http://localhost/callback",
		logoutCallbackURI: "http://localhost/logout/callback",
	}
}
