package config

import (
	"encoding/json"
	"net/http"
)

type IDPortenWellKnown struct {
	Issuer                                 string    `json:"issuer"`
	AuthorizationEndpoint                  string    `json:"authorization_endpoint"`
	PushedAuthorizationRequestEndpoint     string    `json:"pushed_authorization_request_endpoint"`
	TokenEndpoint                          string    `json:"token_endpoint"`
	EndSessionEndpoint                     string    `json:"end_session_endpoint"`
	RevocationEndpoint                     string    `json:"revocation_endpoint"`
	JwksURI                                string    `json:"jwks_uri"`
	ResponseTypesSupported                 []string  `json:"response_types_supported"`
	ResponseModesSupported                 []string  `json:"response_modes_supported"`
	SubjectTypesSupported                  []string  `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported       []string  `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported          []string  `json:"code_challenge_methods_supported"`
	UserInfoEndpoint                       string    `json:"userinfo_endpoint"`
	ScopesSupported                        []string  `json:"scopes_supported"`
	UILocalesSupported                     Supported `json:"ui_locales_supported"`
	ACRValuesSupported                     Supported `json:"acr_values_supported"`
	FrontchannelLogoutSupported            bool      `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported     bool      `json:"frontchannel_logout_session_supported"`
	IntrospectionEndpoint                  string    `json:"introspection_endpoint"`
	TokenEndpointAuthMethodsSupported      []string  `json:"token_endpoint_auth_methods_supported"`
	RequestParameterSupported              bool      `json:"request_parameter_supported"`
	RequestURIParameterSupported           bool      `json:"request_uri_parameter_supported"`
	RequestObjectSigningAlgValuesSupported []string  `json:"request_object_signing_alg_values_supported"`
}

type Supported []string

func (in Supported) Contains(value string) bool {
	for _, allowed := range in {
		if allowed == value {
			return true
		}
	}
	return false
}

func (c *Config) FetchWellKnownConfig() error {
	response, err := http.Get(c.IDPorten.WellKnownURL)
	if err != nil {
		return err
	}

	// can this play with viper in any way?
	if err := json.NewDecoder(response.Body).Decode(&c.IDPorten.WellKnown); err != nil {
		return err
	}
	return nil
}
