package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	log "github.com/sirupsen/logrus"

	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/acr"
)

type Provider interface {
	ACRValuesSupported() Supported
	AuthorizationEndpoint() string
	AuthorizationResponseIssParameterSupported() bool
	EndSessionEndpointURL() url.URL
	JwksFallbackAlg() jwa.KeyAlgorithm
	Issuer() string
	JwksURI() string
	PushedAuthorizationRequestEndpoint() string
	SessionStateRequired() bool
	SidClaimRequired() bool
	TokenEndpoint() string
	UILocalesSupported() Supported
}

type provider struct {
	endSessionEndpointURL *url.URL
	jwksFallbackAlg       jwa.KeyAlgorithm
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

func (p *provider) JwksFallbackAlg() jwa.KeyAlgorithm {
	return p.jwksFallbackAlg
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

func (p *provider) PushedAuthorizationRequestEndpoint() string {
	return p.metadata.PushedAuthorizationRequestEndpoint
}

func (p *provider) SessionStateRequired() bool {
	return len(p.metadata.CheckSessionIframe) > 0
}

func (p *provider) SidClaimRequired() bool {
	return p.metadata.FrontchannelLogoutSupported && p.metadata.FrontchannelLogoutSessionSupported
}

// wellKnownTimeout bounds the fetch of the provider's metadata document at startup.
const wellKnownTimeout = 10 * time.Second

func NewProviderConfig(ctx context.Context, cfg *config.Config, clientAssertionAlg jwa.KeyAlgorithm) (Provider, error) {
	ctx, cancel := context.WithTimeout(ctx, wellKnownTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.OpenID.WellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for well known configuration: %w", err)
	}

	client := &http.Client{Transport: httpinternal.Transport()}

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching well known configuration: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching well known configuration: %s responded with HTTP %d", cfg.OpenID.WellKnownURL, response.StatusCode)
	}

	providerCfg := new(ProviderMetadata)
	if err := json.NewDecoder(response.Body).Decode(providerCfg); err != nil {
		return nil, fmt.Errorf("decoding well known configuration: %w", err)
	}

	err = providerCfg.Validate(cfg.OpenID, clientAssertionAlg)
	if err != nil {
		return nil, fmt.Errorf("validating well known configuration: %w", err)
	}

	endSessionEndpointURL, err := url.Parse(providerCfg.EndSessionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing end session endpoint URL: %w", err)
	}

	providerCfg.Print()

	fallbackAlg, ok := jwa.LookupSignatureAlgorithm(cfg.OpenID.JWKSFallbackAlg)
	if !ok {
		return nil, fmt.Errorf("invalid JWKS fallback algorithm: %q, must be one of %s", cfg.OpenID.JWKSFallbackAlg, jwa.SignatureAlgorithms())
	}

	return &provider{
		endSessionEndpointURL: endSessionEndpointURL,
		jwksFallbackAlg:       fallbackAlg,
		metadata:              providerCfg,
	}, nil
}

type ProviderMetadata struct {
	ACRValuesSupported                         Supported `json:"acr_values_supported"`
	AuthorizationEndpoint                      string    `json:"authorization_endpoint"`
	AuthorizationResponseIssParameterSupported bool      `json:"authorization_response_iss_parameter_supported"`
	CheckSessionIframe                         string    `json:"check_session_iframe"`
	CodeChallengeMethodsSupported              []string  `json:"code_challenge_methods_supported"`
	EndSessionEndpoint                         string    `json:"end_session_endpoint"`
	FrontchannelLogoutSessionSupported         bool      `json:"frontchannel_logout_session_supported"`
	FrontchannelLogoutSupported                bool      `json:"frontchannel_logout_supported"`
	IDTokenSigningAlgValuesSupported           []string  `json:"id_token_signing_alg_values_supported"`
	IntrospectionEndpoint                      string    `json:"introspection_endpoint"`
	Issuer                                     string    `json:"issuer"`
	JwksURI                                    string    `json:"jwks_uri"`
	PushedAuthorizationRequestEndpoint         string    `json:"pushed_authorization_request_endpoint"`
	RequestObjectSigningAlgValuesSupported     []string  `json:"request_object_signing_alg_values_supported"`
	RequestParameterSupported                  bool      `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool      `json:"request_uri_parameter_supported"`
	ResponseModesSupported                     []string  `json:"response_modes_supported"`
	ResponseTypesSupported                     []string  `json:"response_types_supported"`
	RevocationEndpoint                         string    `json:"revocation_endpoint"`
	ScopesSupported                            []string  `json:"scopes_supported"`
	SubjectTypesSupported                      []string  `json:"subject_types_supported"`
	TokenEndpoint                              string    `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string  `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string  `json:"token_endpoint_auth_signing_alg_values_supported"`
	UILocalesSupported                         Supported `json:"ui_locales_supported"`
	UserInfoEndpoint                           string    `json:"userinfo_endpoint"`
}

func (c *ProviderMetadata) Print() {
	log.WithField("logger", "wonderwall.config").
		Debugf("openid provider config: %+v", c)
}

func (c *ProviderMetadata) Validate(cfg config.OpenID, clientAssertionAlg jwa.KeyAlgorithm) error {
	err := c.validateAcrValues(cfg.ACRValues)
	if err != nil {
		return err
	}

	err = c.validateLocaleValues(cfg.UILocales)
	if err != nil {
		return err
	}

	err = c.validateJWKSFallbackAlg(cfg.JWKSFallbackAlg)
	if err != nil {
		return err
	}

	return c.validateClientAssertionSigningAlg(clientAssertionAlg)
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

func (c *ProviderMetadata) validateJWKSFallbackAlg(algorithm string) error {
	// The JWKS is only used to verify id_tokens, so this is the right list.
	if slices.Contains(c.IDTokenSigningAlgValuesSupported, algorithm) {
		return nil
	}

	return fmt.Errorf("identity provider does not support '%s=%s', must be one of %s", config.OpenIDJWKSFallbackAlg, algorithm, c.IDTokenSigningAlgValuesSupported)
}

func (c *ProviderMetadata) validateClientAssertionSigningAlg(algorithm jwa.KeyAlgorithm) error {
	if len(c.TokenEndpointAuthSigningAlgValuesSupported) == 0 || algorithm == nil {
		return nil
	}

	if slices.Contains(c.TokenEndpointAuthSigningAlgValuesSupported, algorithm.String()) {
		return nil
	}

	return fmt.Errorf("identity provider does not support client assertion signing algorithm %q, must be one of %s", algorithm, c.TokenEndpointAuthSigningAlgValuesSupported)
}

type Supported []string

func (in Supported) Contains(value string) bool {
	return slices.Contains(in, value)
}
