package mock

import (
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type TestClientConfiguration struct {
	ClientID              string
	ClientJWK             jwk.Key
	CallbackURI           string
	LogoutCallbackURI     string
	PostLogoutRedirectURI string
	Scopes                scopes.Scopes
	ACRValues             string
	UILocales             string
	WellKnownURL          string
}

func (c *TestClientConfiguration) GetCallbackURI() string {
	return c.CallbackURI
}

func (c *TestClientConfiguration) GetClientID() string {
	return c.ClientID
}

func (c *TestClientConfiguration) GetClientJWK() jwk.Key {
	return c.ClientJWK
}

func (c *TestClientConfiguration) GetLogoutCallbackURI() string {
	return c.LogoutCallbackURI
}

func (c *TestClientConfiguration) GetPostLogoutRedirectURI() string {
	return c.PostLogoutRedirectURI
}

func (c *TestClientConfiguration) GetScopes() scopes.Scopes {
	return c.Scopes
}

func (c *TestClientConfiguration) GetACRValues() string {
	return c.ACRValues
}

func (c *TestClientConfiguration) GetUILocales() string {
	return c.UILocales
}

func (c *TestClientConfiguration) GetWellKnownURL() string {
	return c.WellKnownURL
}

func (c *TestClientConfiguration) Print() {}

func clientConfiguration(cfg *config.Config) *TestClientConfiguration {
	key, err := crypto.NewJwk()
	if err != nil {
		panic(err)
	}

	return &TestClientConfiguration{
		ClientID:              cfg.OpenID.ClientID,
		ClientJWK:             key,
		CallbackURI:           "http://localhost/callback",
		LogoutCallbackURI:     "http://localhost/logout/callback",
		WellKnownURL:          "",
		UILocales:             "nb",
		ACRValues:             "Level4",
		PostLogoutRedirectURI: "",
		Scopes:                scopes.DefaultScopes().WithAdditional(cfg.OpenID.Scopes...),
	}
}
