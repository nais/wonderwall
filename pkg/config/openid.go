package config

import (
	flag "github.com/spf13/pflag"
)

const (
	OpenIDProvider              = "openid.provider"
	OpenIDClientID              = "openid.client-id"
	OpenIDClientJWK             = "openid.client-jwk"
	OpenIDPostLogoutRedirectURI = "openid.post-logout-redirect-uri"
	OpenIDScopes                = "openid.scopes"
	OpenIDWellKnownURL          = "openid.well-known-url"
	OpenIDACRValues             = "openid.acr-values"
	OpenIDUILocales             = "openid.ui-locales"
)

type OpenID struct {
	Provider              Provider `json:"provider"`
	ClientID              string   `json:"client-id"`
	ClientJWK             string   `json:"client-jwk"`
	PostLogoutRedirectURI string   `json:"post-logout-redirect-uri"`
	Scopes                []string `json:"scopes"`
	WellKnownURL          string   `json:"well-known-url"`
	ACRValues             string   `json:"acr-values"`
	UILocales             string   `json:"ui-locales"`
}

type Provider string

const (
	ProviderAzure    Provider = "azure"
	ProviderIDPorten Provider = "idporten"
	ProviderOpenID   Provider = "openid"
)

func openIDFlags() {
	flag.String(OpenIDClientID, "", "Client ID for the OpenID client.")
	flag.String(OpenIDClientJWK, "", "JWK containing the private key for the OpenID client in string format.")
	flag.String(OpenIDPostLogoutRedirectURI, "", "URI for redirecting the user after successful logout at the Identity Provider.")
	flag.StringSlice(OpenIDScopes, []string{}, "List of additional scopes (other than 'openid') that should be used during the login flow.")
	flag.String(OpenIDWellKnownURL, "", "URI to the well-known OpenID Configuration metadata document.")

	flag.String(OpenIDACRValues, "", "Space separated string that configures the default security level (acr_values) parameter for authorization requests.")
	flag.String(OpenIDUILocales, "", "Space-separated string that configures the default UI locale (ui_locales) parameter for OAuth2 consent screen.")
}
