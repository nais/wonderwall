package config

import (
	"github.com/spf13/viper"

	"github.com/nais/wonderwall/pkg/openid"
)

type idporten struct {
	*BaseConfig
}

func idportenFlags() {
	viper.BindEnv(OpenIDClientID, "IDPORTEN_CLIENT_ID")
	viper.BindEnv(OpenIDClientJWK, "IDPORTEN_CLIENT_JWK")
	viper.BindEnv(OpenIDWellKnownURL, "IDPORTEN_WELL_KNOWN_URL")

	viper.SetDefault(OpenIDPostLogoutRedirectURI, "https://www.nav.no")
	viper.SetDefault(OpenIDACRValues, "Level4")
	viper.SetDefault(OpenIDUILocales, "nb")
}

func (in *BaseConfig) IDPorten() openid.ClientConfiguration {
	return &idporten{
		BaseConfig: in,
	}
}
