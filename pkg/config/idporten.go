package config

import (
	"github.com/spf13/viper"
)

const (
	IDPortenAcrLevel3 = "Level3"
	IDPortenAcrLevel4 = "Level4"
)

func idportenFlags() {
	viper.BindEnv(OpenIDClientID, "IDPORTEN_CLIENT_ID")
	viper.BindEnv(OpenIDClientJWK, "IDPORTEN_CLIENT_JWK")
	viper.BindEnv(OpenIDWellKnownURL, "IDPORTEN_WELL_KNOWN_URL")

	viper.SetDefault(OpenIDPostLogoutRedirectURI, "https://www.nav.no/no/utlogget")
	viper.SetDefault(OpenIDACRValues, IDPortenAcrLevel4)
	viper.SetDefault(OpenIDUILocales, "nb")
}
