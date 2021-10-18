package openid

import (
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/nais/wonderwall/pkg/scopes"
)

type ClientConfiguration interface {
	GetClientID() string
	GetClientJWK() jwk.Key
	GetPostLogoutRedirectURI() string
	GetRedirectURI() string
	GetScopes() scopes.Scopes
	GetACRValues() string
	GetUILocales() string
	GetWellKnownURL() string
}
