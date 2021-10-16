package openid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
)

type Configuration struct {
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

func FetchWellKnownConfig(wellKnownURI string) (*Configuration, error) {
	response, err := http.Get(wellKnownURI)
	if err != nil {
		return nil, fmt.Errorf("fetching well known configuration: %w", err)
	}

	var cfg Configuration
	if err := json.NewDecoder(response.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decoding well known configuration: %w", err)
	}

	return &cfg, nil
}

func (c *Configuration) FetchJwkSet(ctx context.Context) (*jwk.Set, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jwkSet, err := jwk.Fetch(ctx, c.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetching jwks: %w", err)
	}

	return &jwkSet, nil
}
