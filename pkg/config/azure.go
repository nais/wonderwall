package config

import (
	"github.com/spf13/viper"
)

func azureFlags() {
	viper.BindEnv(OpenIDClientID, "AZURE_APP_CLIENT_ID")
	viper.BindEnv(OpenIDClientJWK, "AZURE_APP_JWK")
	viper.BindEnv(OpenIDWellKnownURL, "AZURE_APP_WELL_KNOWN_URL")
}
