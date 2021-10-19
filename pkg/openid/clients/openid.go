package clients

import (
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type BaseConfig struct {
	config.OpenID
	clientJwk   jwk.Key
	redirectURI string
}

func (in *BaseConfig) GetRedirectURI() string {
	return in.redirectURI
}

func (in *BaseConfig) GetClientID() string {
	return in.ClientID
}

func (in *BaseConfig) GetClientJWK() jwk.Key {
	return in.clientJwk
}

func (in *BaseConfig) GetPostLogoutRedirectURI() string {
	return in.PostLogoutRedirectURI
}

func (in *BaseConfig) GetScopes() scopes.Scopes {
	return scopes.DefaultScopes().WithAdditional(in.Scopes...)
}

func (in *BaseConfig) GetACRValues() string {
	return in.ACRValues
}

func (in *BaseConfig) GetUILocales() string {
	return in.UILocales
}

func (in *BaseConfig) GetWellKnownURL() string {
	return in.WellKnownURL
}

func NewBaseConfig(cfg config.Config, clientJwk jwk.Key, redirectURI string) *BaseConfig {
	return &BaseConfig{
		OpenID:      cfg.OpenID,
		clientJwk:   clientJwk,
		redirectURI: redirectURI,
	}
}
