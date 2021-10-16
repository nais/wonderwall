package config

import (
	"github.com/spf13/viper"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/scopes"
)

type azure struct {
	*BaseConfig
}

func azureFlags() {
	viper.BindEnv(OpenIDClientID, "AZURE_APP_CLIENT_ID")
	viper.BindEnv(OpenIDClientJWK, "AZURE_APP_JWK")
	viper.BindEnv(OpenIDRedirectURI, "AZURE_APP_REDIRECT_URI")
	viper.BindEnv(OpenIDWellKnownURL, "AZURE_APP_WELL_KNOWN_URL")
}

func (in *BaseConfig) Azure() openid.ClientConfiguration {
	return &azure{
		BaseConfig: in,
	}
}

func (in *azure) GetScopes() scopes.Scopes {
	return scopes.Defaults().
		WithAzureScope(in.ClientID).
		WithAdditional(in.Scopes...)
}
