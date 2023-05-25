package config

import (
	"github.com/spf13/viper"
)

const (
	IDPortenAcrLevel3           = "Level3"
	IDPortenAcrLevelSubstantial = "idporten-loa-substantial"
	IDPortenAcrLevel4           = "Level4"
	IDPortenAcrLevelHigh        = "idporten-loa-high"
)

// IDPortenAcrMapping is a translation table of valid acr_values for migrating between old and new ID-porten.
var IDPortenAcrMapping = map[string]string{
	IDPortenAcrLevel3:           IDPortenAcrLevelSubstantial,
	IDPortenAcrLevelSubstantial: IDPortenAcrLevel3,
	IDPortenAcrLevel4:           IDPortenAcrLevelHigh,
	IDPortenAcrLevelHigh:        IDPortenAcrLevel4,
}

func idportenFlags() {
	viper.BindEnv(OpenIDClientID, "IDPORTEN_CLIENT_ID")
	viper.BindEnv(OpenIDClientJWK, "IDPORTEN_CLIENT_JWK")
	viper.BindEnv(OpenIDWellKnownURL, "IDPORTEN_WELL_KNOWN_URL")

	viper.SetDefault(OpenIDPostLogoutRedirectURI, "https://www.nav.no/no/utlogget")
	viper.SetDefault(OpenIDACRValues, IDPortenAcrLevel4) // TODO - change to new value after migration
	viper.SetDefault(OpenIDUILocales, "nb")
}
