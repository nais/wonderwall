package config

import (
	"github.com/lestrrat-go/jwx/jwk"
	flag "github.com/spf13/pflag"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/scopes"
)

const (
	OpenIDProvider              = "openid.provider"
	OpenIDClientID              = "openid.client-id"
	OpenIDClientJWK             = "openid.client-jwk"
	OpenIDPostLogoutRedirectURI = "openid.post-logout-redirect-uri"
	OpenIDRedirectURI           = "openid.redirect-uri"
	OpenIDScopes                = "openid.scopes"
	OpenIDWellKnownURL          = "openid.well-known-url"
	OpenIDACRValuesEnabled      = "openid.acr-values.enabled"
	OpenIDACRValuesValue        = "openid.acr-values.value"
	OpenIDUILocalesEnabled      = "openid.ui-locales.enabled"
	OpenIDUILocalesValue        = "openid.ui-locales.value"
)

type OpenID struct {
	Provider              Provider                     `json:"provider"`
	ClientID              string                       `json:"client-id"`
	ClientJWK             string                       `json:"client-jwk"`
	PostLogoutRedirectURI string                       `json:"post-logout-redirect-uri"`
	RedirectURI           string                       `json:"redirect-uri"`
	Scopes                []string                     `json:"scopes"`
	WellKnownURL          string                       `json:"well-known-url"`
	ACRValues             openid.OptionalConfiguration `json:"acr-values"`
	UILocales             openid.OptionalConfiguration `json:"ui-locales"`
}

type Provider string

const (
	ProviderAzure    Provider = "azure"
	ProviderIDPorten Provider = "idporten"
	ProviderOpenID   Provider = "openid"
)

type BaseConfig struct {
	OpenID
	clientJwk jwk.Key
}

func (in *BaseConfig) GetRedirectURI() string {
	return in.RedirectURI
}

func (in *BaseConfig) GetClientID() string {
	return in.ClientID
}

func (in *BaseConfig) GetClientJWK() jwk.Key {
	return in.clientJwk
}

func (in *BaseConfig) GetPostLogoutRedirectURI() string {
	return in.PostLogoutRedirectURI
}

func (in *BaseConfig) GetScopes() scopes.Scopes {
	return scopes.Defaults().WithAdditional(in.Scopes...)
}

func (in *BaseConfig) GetACRValues() openid.OptionalConfiguration {
	return openid.OptionalConfiguration{
		Enabled: in.ACRValues.Enabled,
		Value:   in.ACRValues.Value,
	}
}

func (in *BaseConfig) GetUILocales() openid.OptionalConfiguration {
	return openid.OptionalConfiguration{
		Enabled: in.UILocales.Enabled,
		Value:   in.UILocales.Value,
	}
}

func (in *BaseConfig) GetWellKnownURL() string {
	return in.WellKnownURL
}

func (c *Config) NewBaseConfig(clientJwk jwk.Key) *BaseConfig {
	return &BaseConfig{
		OpenID:    c.OpenID,
		clientJwk: clientJwk,
	}
}

func openIDFlags() {
	flag.String(OpenIDClientID, "", "Client ID for the OpenID client.")
	flag.String(OpenIDClientJWK, "", "JWK containing the private key for the OpenID client in string format.")
	flag.String(OpenIDPostLogoutRedirectURI, "", "URI for redirecting the user after successful logout at the Identity Provider.")
	flag.String(OpenIDRedirectURI, "", "Redirect URI for the OpenID client that should be used in authorization requests.")
	flag.StringSlice(OpenIDScopes, []string{}, "List of additional scopes (other than 'openid') that should be used during the login flow.")
	flag.String(OpenIDWellKnownURL, "", "URI to the well-known OpenID Configuration metadata document.")

	flag.Bool(OpenIDACRValuesEnabled, false, "Toggle for setting the security level (acr_values) parameter for authorization requests.")
	flag.String(OpenIDACRValuesValue, "", "Space separated string that configures the requested acr_values.")
	flag.Bool(OpenIDUILocalesEnabled, false, "Toggle for setting the UI locale parameter for authorization requests.")
	flag.String(OpenIDUILocalesValue, "", "Space-separated string that configures the default locales for OAuth2 consent screen.")
}
