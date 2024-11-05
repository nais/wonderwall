package config

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/nais/wonderwall/pkg/openid/acr"
)

type Provider string

const (
	ProviderAzure    Provider = "azure"
	ProviderIDPorten Provider = "idporten"
	ProviderOpenID   Provider = "openid"
)

type OpenID struct {
	ACRValues             string   `json:"acr-values"`
	Audiences             []string `json:"audiences"`
	ClientID              string   `json:"client-id"`
	ClientJWK             string   `json:"client-jwk"`
	ClientSecret          string   `json:"client-secret"`
	PostLogoutRedirectURI string   `json:"post-logout-redirect-uri"`
	Provider              Provider `json:"provider"`
	ResourceIndicator     string   `json:"resource-indicator"`
	Scopes                []string `json:"scopes"`
	UILocales             string   `json:"ui-locales"`
	WellKnownURL          string   `json:"well-known-url"`
}

func (in OpenID) TrustedAudiences() map[string]bool {
	m := make(map[string]bool)
	m[in.ClientID] = true
	for _, aud := range in.Audiences {
		m[aud] = true
	}

	return m
}

const (
	OpenIDACRValues             = "openid.acr-values"
	OpenIDAudiences             = "openid.audiences"
	OpenIDClientID              = "openid.client-id"
	OpenIDClientJWK             = "openid.client-jwk"
	OpenIDClientSecret          = "openid.client-secret"
	OpenIDPostLogoutRedirectURI = "openid.post-logout-redirect-uri"
	OpenIDProvider              = "openid.provider"
	OpenIDResourceIndicator     = "openid.resource-indicator"
	OpenIDScopes                = "openid.scopes"
	OpenIDUILocales             = "openid.ui-locales"
	OpenIDWellKnownURL          = "openid.well-known-url"
)

func openidFlags() {
	flag.String(OpenIDACRValues, "", "Space separated string that configures the default security level (acr_values) parameter for authorization requests.")
	flag.StringSlice(OpenIDAudiences, []string{}, "List of additional trusted audiences (other than the client_id) for OpenID Connect id_token validation.")
	flag.String(OpenIDClientID, "", "Client ID for the OpenID client.")
	flag.String(OpenIDClientJWK, "", "JWK containing the private key for the OpenID client in string format. If configured, this takes precedence over 'openid.client-secret'.")
	flag.String(OpenIDClientSecret, "", "Client secret for the OpenID client. Overridden by 'openid.client-jwk', if configured.")
	flag.String(OpenIDPostLogoutRedirectURI, "", "URI for redirecting the user after successful logout at the Identity Provider.")
	flag.String(OpenIDProvider, string(ProviderOpenID), "Provider configuration to load and use, either 'openid', 'azure', 'idporten'.")
	flag.String(OpenIDResourceIndicator, "", "OAuth2 resource indicator to include in authorization request for acquiring audience-restricted tokens.")
	flag.StringSlice(OpenIDScopes, []string{}, "Comma separated list of additional scopes (other than 'openid') that should be used during the login flow.")
	flag.String(OpenIDUILocales, "", "Space-separated string that configures the default UI locale (ui_locales) parameter for OAuth2 consent screen.")
	flag.String(OpenIDWellKnownURL, "", "URI to the well-known OpenID Configuration metadata document.")
}

func resolveOpenIdProvider() {
	switch Provider(viper.GetString(OpenIDProvider)) {
	case ProviderIDPorten:
		viper.BindEnv(OpenIDClientID, "IDPORTEN_CLIENT_ID")
		viper.BindEnv(OpenIDClientJWK, "IDPORTEN_CLIENT_JWK")
		viper.BindEnv(OpenIDWellKnownURL, "IDPORTEN_WELL_KNOWN_URL")

		viper.SetDefault(OpenIDACRValues, acr.IDPortenLevelHigh)
		viper.SetDefault(OpenIDUILocales, "nb")
	case ProviderAzure:
		viper.BindEnv(OpenIDClientID, "AZURE_APP_CLIENT_ID")
		viper.BindEnv(OpenIDClientJWK, "AZURE_APP_JWK")
		viper.BindEnv(OpenIDWellKnownURL, "AZURE_APP_WELL_KNOWN_URL")
	default:
		viper.Set(OpenIDProvider, ProviderOpenID)
	}
}
