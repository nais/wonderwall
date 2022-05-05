package mock

import (
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type TestClientConfiguration struct {
	ClientID              string
	ClientJWK             jwk.Key
	RedirectURI           string
	PostLogoutRedirectURI string
	Scopes                scopes.Scopes
	ACRValues             string
	UILocales             string
	WellKnownURL          string
}

func (c TestClientConfiguration) GetRedirectURI() string {
	return c.RedirectURI
}

func (c TestClientConfiguration) GetClientID() string {
	return c.ClientID
}

func (c TestClientConfiguration) GetClientJWK() jwk.Key {
	return c.ClientJWK
}

func (c TestClientConfiguration) GetPostLogoutRedirectURI() string {
	return c.PostLogoutRedirectURI
}

func (c TestClientConfiguration) GetScopes() scopes.Scopes {
	return c.Scopes
}

func (c TestClientConfiguration) GetACRValues() string {
	return c.ACRValues
}

func (c TestClientConfiguration) GetUILocales() string {
	return c.UILocales
}

func (c TestClientConfiguration) GetWellKnownURL() string {
	return c.WellKnownURL
}

func clientConfiguration() TestClientConfiguration {
	key, err := crypto.NewJwk()
	if err != nil {
		panic(err)
	}

	return TestClientConfiguration{
		ClientID:              "client_id",
		ClientJWK:             key,
		RedirectURI:           "http://localhost/callback",
		WellKnownURL:          "",
		UILocales:             "nb",
		ACRValues:             "Level4",
		PostLogoutRedirectURI: "",
		Scopes:                scopes.DefaultScopes(),
	}
}
