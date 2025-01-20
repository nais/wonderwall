package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/v2/jwa"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/acr"
)

type Provider interface {
	ACRValuesSupported() Supported
	AuthorizationEndpoint() string
	AuthorizationResponseIssParameterSupported() bool
	EndSessionEndpointURL() url.URL
	IDTokenSigningAlg() jwa.KeyAlgorithm
	Issuer() string
	JwksURI() string
	SessionStateRequired() bool
	SidClaimRequired() bool
	TokenEndpoint() string
	UILocalesSupported() Supported
}

type provider struct {
	endSessionEndpointURL *url.URL
	idTokenSigningAlg     jwa.KeyAlgorithm
	metadata              *ProviderMetadata
}

func (p *provider) AuthorizationResponseIssParameterSupported() bool {
	return p.metadata.AuthorizationResponseIssParameterSupported
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

func (p *provider) IDTokenSigningAlg() jwa.KeyAlgorithm {
	return p.idTokenSigningAlg
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

func NewProviderConfig(cfg *config.Config) (Provider, error) {
	response, err := http.Get(cfg.OpenID.WellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("fetching well known configuration: %w", err)
	}
	defer response.Body.Close()

	providerCfg := new(ProviderMetadata)
	if err := json.NewDecoder(response.Body).Decode(providerCfg); err != nil {
		return nil, fmt.Errorf("decoding well known configuration: %w", err)
	}

	err = providerCfg.Validate(cfg.OpenID)
	if err != nil {
		return nil, fmt.Errorf("validating well known configuration: %w", err)
	}

	endSessionEndpointURL, err := url.Parse(providerCfg.EndSessionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing end session endpoint URL: %w", err)
	}

	providerCfg.Print()

	return &provider{
		endSessionEndpointURL: endSessionEndpointURL,
		idTokenSigningAlg:     jwa.SignatureAlgorithm(cfg.OpenID.IDTokenSigningAlg),
		metadata:              providerCfg,
	}, nil
}

type ProviderMetadata struct {
	Issuer                                     string    `json:"issuer"`
	AuthorizationEndpoint                      string    `json:"authorization_endpoint"`
	PushedAuthorizationRequestEndpoint         string    `json:"pushed_authorization_request_endpoint"`
	TokenEndpoint                              string    `json:"token_endpoint"`
	EndSessionEndpoint                         string    `json:"end_session_endpoint"`
	RevocationEndpoint                         string    `json:"revocation_endpoint"`
	JwksURI                                    string    `json:"jwks_uri"`
	ResponseTypesSupported                     []string  `json:"response_types_supported"`
	ResponseModesSupported                     []string  `json:"response_modes_supported"`
	SubjectTypesSupported                      []string  `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string  `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string  `json:"code_challenge_methods_supported"`
	UserInfoEndpoint                           string    `json:"userinfo_endpoint"`
	ScopesSupported                            []string  `json:"scopes_supported"`
	UILocalesSupported                         Supported `json:"ui_locales_supported"`
	ACRValuesSupported                         Supported `json:"acr_values_supported"`
	AuthorizationResponseIssParameterSupported bool      `json:"authorization_response_iss_parameter_supported"`
	FrontchannelLogoutSupported                bool      `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported         bool      `json:"frontchannel_logout_session_supported"`
	IntrospectionEndpoint                      string    `json:"introspection_endpoint"`
	TokenEndpointAuthMethodsSupported          []string  `json:"token_endpoint_auth_methods_supported"`
	RequestParameterSupported                  bool      `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool      `json:"request_uri_parameter_supported"`
	RequestObjectSigningAlgValuesSupported     []string  `json:"request_object_signing_alg_values_supported"`
	CheckSessionIframe                         string    `json:"check_session_iframe"`
}

func (c *ProviderMetadata) Print() {
	log.WithField("logger", "wonderwall.config").
		Debugf("openid provider config: %+v", c)
}

func (c *ProviderMetadata) Validate(cfg config.OpenID) error {
	err := c.validateAcrValues(cfg.ACRValues)
	if err != nil {
		return err
	}

	err = c.validateLocaleValues(cfg.UILocales)
	if err != nil {
		return err
	}

	err = c.validateIDTokenSigningAlg(cfg.IDTokenSigningAlg)
	if err != nil {
		return err
	}

	return nil
}

func (c *ProviderMetadata) validateAcrValues(acrValue string) error {
	if len(acrValue) == 0 || c.ACRValuesSupported.Contains(acrValue) {
		return nil
	}

	translatedAcr, ok := acr.IDPortenLegacyMapping[acrValue]
	if ok && c.ACRValuesSupported.Contains(translatedAcr) {
		return nil
	}

	return fmt.Errorf("identity provider does not support '%s=%s', must be one of %s", config.OpenIDACRValues, acrValue, c.ACRValuesSupported)
}

func (c *ProviderMetadata) validateLocaleValues(locale string) error {
	if len(locale) == 0 || c.UILocalesSupported.Contains(locale) {
		return nil
	}

	return fmt.Errorf("identity provider does not support '%s=%s', must be one of %s", config.OpenIDUILocales, locale, c.UILocalesSupported)
}

func (c *ProviderMetadata) validateIDTokenSigningAlg(algorithm string) error {
	for _, alg := range c.IDTokenSigningAlgValuesSupported {
		if alg == algorithm {
			return nil
		}
	}

	return fmt.Errorf("identity provider does not support '%s=%s', must be one of %s", config.OpenIDIDTokenSigningAlg, algorithm, c.IDTokenSigningAlgValuesSupported)
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
