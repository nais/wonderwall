package mock

import (
	"context"
	"net/url"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

type TestProvider struct {
	JwksPair *crypto.JwkSet
}

func (p *TestProvider) GetPublicJwkSet(_ context.Context) (*jwk.Set, error) {
	return &p.JwksPair.Public, nil
}

func (p *TestProvider) RefreshPublicJwkSet(_ context.Context) (*jwk.Set, error) {
	return &p.JwksPair.Public, nil
}

func (p *TestProvider) PrivateJwkSet() *jwk.Set {
	return &p.JwksPair.Private
}

func NewTestJwksProvider() *TestProvider {
	jwksPair, err := crypto.NewJwkSet()
	if err != nil {
		log.Fatal(err)
	}

	return &TestProvider{
		JwksPair: jwksPair,
	}
}

type TestProviderConfiguration struct {
	Cfg      *config.Config
	Metadata *openidconfig.ProviderMetadata
}

func (t *TestProviderConfiguration) AuthorizationEndpoint() string {
	return t.Metadata.AuthorizationEndpoint
}

func (t *TestProviderConfiguration) AuthorizationResponseIssParameterSupported() bool {
	return t.Metadata.AuthorizationResponseIssParameterSupported
}

func (t *TestProviderConfiguration) EndSessionEndpointURL() url.URL {
	u, _ := url.Parse(t.Metadata.EndSessionEndpoint)
	return *u
}

func (t *TestProviderConfiguration) IDTokenSigningAlg() jwa.KeyAlgorithm {
	return jwa.RS256
}

func (t *TestProviderConfiguration) Issuer() string {
	return t.Metadata.Issuer
}

func (t *TestProviderConfiguration) JwksURI() string {
	return t.Metadata.JwksURI
}

func (t *TestProviderConfiguration) TokenEndpoint() string {
	return t.Metadata.TokenEndpoint
}

func (t *TestProviderConfiguration) ACRValuesSupported() openidconfig.Supported {
	return t.Metadata.ACRValuesSupported
}

func (t *TestProviderConfiguration) UILocalesSupported() openidconfig.Supported {
	return t.Metadata.UILocalesSupported
}

func (t *TestProviderConfiguration) Name() string {
	return string(t.Cfg.OpenID.Provider)
}

func (t *TestProviderConfiguration) PushedAuthorizationRequestEndpoint() string {
	return t.Metadata.PushedAuthorizationRequestEndpoint
}

func (t *TestProviderConfiguration) SessionStateRequired() bool {
	return len(t.Metadata.CheckSessionIframe) > 0
}

func (t *TestProviderConfiguration) SidClaimRequired() bool {
	return t.Metadata.FrontchannelLogoutSupported && t.Metadata.FrontchannelLogoutSessionSupported
}

func (t *TestProviderConfiguration) SetAuthorizationEndpoint(url string) {
	t.Metadata.AuthorizationEndpoint = url
}

func (t *TestProviderConfiguration) SetCheckSessionIframe(url string) {
	t.Metadata.CheckSessionIframe = url
}

func (t *TestProviderConfiguration) SetEndSessionEndpoint(url string) {
	t.Metadata.EndSessionEndpoint = url
}

func (t *TestProviderConfiguration) SetFrontchannelLogoutSupported(val bool) {
	t.Metadata.FrontchannelLogoutSupported = val
}

func (t *TestProviderConfiguration) SetFrontchannelLogoutSessionSupported(val bool) {
	t.Metadata.FrontchannelLogoutSessionSupported = val
}

func (t *TestProviderConfiguration) SetIssuer(url string) {
	t.Metadata.Issuer = url
}

func (t *TestProviderConfiguration) SetJwksURI(url string) {
	t.Metadata.JwksURI = url
}

func (t *TestProviderConfiguration) SetPushedAuthorizationRequestEndpoint(url string) {
	t.Metadata.PushedAuthorizationRequestEndpoint = url
}

func (t *TestProviderConfiguration) SetTokenEndpoint(url string) {
	t.Metadata.TokenEndpoint = url
}

func (t *TestProviderConfiguration) WithFrontChannelLogoutSupport() {
	t.SetFrontchannelLogoutSupported(true)
	t.SetFrontchannelLogoutSessionSupported(true)
}

func (t *TestProviderConfiguration) WithCheckSessionIFrameSupport(url string) {
	t.SetCheckSessionIframe(url)
}

func (t *TestProviderConfiguration) WithAuthorizationResponseIssParameterSupported() {
	t.Metadata.AuthorizationResponseIssParameterSupported = true
}

func providerConfiguration(cfg *config.Config) *TestProviderConfiguration {
	return &TestProviderConfiguration{
		Cfg: cfg,
		Metadata: &openidconfig.ProviderMetadata{
			ACRValuesSupported: openidconfig.Supported{"idporten-loa-substantial", "idporten-loa-high"},
			UILocalesSupported: openidconfig.Supported{"nb", "nb", "en", "se"},
		},
	}
}
