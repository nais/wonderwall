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
	viper.BindEnv(OpenIDRedirectURI, "IDPORTEN_REDIRECT_URI")
	viper.BindEnv(OpenIDWellKnownURL, "IDPORTEN_WELL_KNOWN_URL")

	viper.SetDefault(OpenIDPostLogoutRedirectURI, "https://www.nav.no")
	viper.SetDefault(OpenIDACRValuesEnabled, true)
	viper.SetDefault(OpenIDACRValuesValue, "Level4")
	viper.SetDefault(OpenIDUILocalesEnabled, true)
	viper.SetDefault(OpenIDUILocalesValue, "nb")
}

func (in *BaseConfig) IDPorten() openid.ClientConfiguration {
	return &idporten{
		BaseConfig: in,
	}
}
