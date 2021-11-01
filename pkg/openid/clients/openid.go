package clients

import (
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type OpenIDConfig struct {
	config.OpenID
	clientJwk   jwk.Key
	redirectURI string
}

func (in *OpenIDConfig) GetRedirectURI() string {
	return in.redirectURI
}

func (in *OpenIDConfig) GetClientID() string {
	return in.ClientID
}

func (in *OpenIDConfig) GetClientJWK() jwk.Key {
	return in.clientJwk
}

func (in *OpenIDConfig) GetPostLogoutRedirectURI() string {
	return in.PostLogoutRedirectURI
}

func (in *OpenIDConfig) GetScopes() scopes.Scopes {
	return scopes.DefaultScopes().WithAdditional(in.Scopes...)
}

func (in *OpenIDConfig) GetACRValues() string {
	return in.ACRValues
}

func (in *OpenIDConfig) GetUILocales() string {
	return in.UILocales
}

func (in *OpenIDConfig) GetWellKnownURL() string {
	return in.WellKnownURL
}

func NewOpenIDConfig(cfg config.Config, clientJwk jwk.Key, redirectURI string) *OpenIDConfig {
	return &OpenIDConfig{
		OpenID:      cfg.OpenID,
		clientJwk:   clientJwk,
		redirectURI: redirectURI,
	}
}
