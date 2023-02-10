package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"

	wonderwallconfig "github.com/nais/wonderwall/pkg/config"
)

type Provider interface {
	AuthorizationEndpoint() string
	EndSessionEndpointURL() url.URL
	Issuer() string
	JwksURI() string
	TokenEndpoint() string

	ACRValuesSupported() Supported
	UILocalesSupported() Supported

	SessionStateRequired() bool
	SidClaimRequired() bool
}

type provider struct {
	endSessionEndpointURL *url.URL
	metadata              *ProviderMetadata
}

func (p *provider) AuthorizationEndpoint() string {
	return p.metadata.AuthorizationEndpoint
}

func (p *provider) EndSessionEndpointURL() url.URL {
	return *p.endSessionEndpointURL
}

func (p *provider) TokenEndpoint() string {
	return p.metadata.TokenEndpoint
}

func (p *provider) Issuer() string {
	return p.metadata.Issuer
}

func (p *provider) JwksURI() string {
	return p.metadata.JwksURI
}

func (p *provider) ACRValuesSupported() Supported {
	return p.metadata.ACRValuesSupported
}

func (p *provider) UILocalesSupported() Supported {
	return p.metadata.UILocalesSupported
}

func (p *provider) SessionStateRequired() bool {
	return len(p.metadata.CheckSessionIframe) > 0
}

func (p *provider) SidClaimRequired() bool {
	return p.metadata.FrontchannelLogoutSupported && p.metadata.FrontchannelLogoutSessionSupported
}

func NewProviderConfig(cfg *wonderwallconfig.Config) (Provider, error) {
	response, err := http.Get(cfg.OpenID.WellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("fetching well known configuration: %w", err)
	}
	defer response.Body.Close()

	providerCfg := new(ProviderMetadata)
	if err := json.NewDecoder(response.Body).Decode(providerCfg); err != nil {
		return nil, fmt.Errorf("decoding well known configuration: %w", err)
	}

	acrValues := cfg.OpenID.ACRValues
	if len(acrValues) > 0 && !providerCfg.ACRValuesSupported.Contains(acrValues) {
		return nil, fmt.Errorf("identity provider does not support '%s=%s'", wonderwallconfig.OpenIDACRValues, acrValues)
	}

	uiLocales := cfg.OpenID.UILocales
	if len(uiLocales) > 0 && !providerCfg.UILocalesSupported.Contains(uiLocales) {
		return nil, fmt.Errorf("identity provider does not support '%s=%s'", wonderwallconfig.OpenIDUILocales, acrValues)
	}

	endSessionEndpointURL, err := url.Parse(providerCfg.EndSessionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing end session endpoint URL: %w", err)
	}

	providerCfg.Print()

	return &provider{
		endSessionEndpointURL: endSessionEndpointURL,
		metadata:              providerCfg,
	}, nil
}

type ProviderMetadata struct {
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
	CheckSessionIframe                     string    `json:"check_session_iframe"`
}

func (c *ProviderMetadata) Print() {
	logger := log.WithField("logger", "openid.config.provider")

	logger.Info("😗 openid provider configuration 😗")
	logger.Infof("%#v", *c)
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
