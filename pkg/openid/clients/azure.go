package clients

import (
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type azure struct {
	*BaseConfig
}

func (in *BaseConfig) Azure() Configuration {
	return &azure{
		BaseConfig: in,
	}
}

func (in *azure) GetScopes() scopes.Scopes {
	return scopes.DefaultScopes().
		WithAzureScope(in.ClientID).
		WithAdditional(in.Scopes...)
}
