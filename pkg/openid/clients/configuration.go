package clients

import (
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type Configuration interface {
	GetClientID() string
	GetClientJWK() jwk.Key
	GetPostLogoutRedirectURI() string
	GetCallbackURI() string
	GetLogoutCallbackURI() string
	GetScopes() scopes.Scopes
	GetACRValues() string
	GetUILocales() string
	GetWellKnownURL() string
}
