package clients

import (
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type azure struct {
	*OpenIDConfig
}

func (in *OpenIDConfig) Azure() Configuration {
	return &azure{
		OpenIDConfig: in,
	}
}

func (in *azure) GetScopes() scopes.Scopes {
	return scopes.DefaultScopes().
		WithAzureScope(in.ClientID).
		WithAdditional(in.Scopes...)
}
