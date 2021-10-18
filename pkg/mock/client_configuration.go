package mock

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/nais/wonderwall/pkg/scopes"
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
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key, err := jwk.New(privateKey)
	if err != nil {
		panic(err)
	}
	key.Set(jwk.AlgorithmKey, jwa.RS256)
	key.Set(jwk.KeyTypeKey, jwa.RSA)
	key.Set(jwk.KeyIDKey, uuid.New().String())

	return TestClientConfiguration{
		ClientID:              "client_id",
		ClientJWK:             key,
		RedirectURI:           "http://localhost/callback",
		WellKnownURL:          "",
		UILocales:             "nb",
		ACRValues:             "Level4",
		PostLogoutRedirectURI: "",
		Scopes:                scopes.Defaults(),
	}
}
