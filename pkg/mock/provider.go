package mock

import (
	"context"
	"net/url"

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
	cfg      *config.Config
	metadata *openidconfig.ProviderMetadata
}

func (t *TestProviderConfiguration) AuthorizationEndpoint() string {
	return t.metadata.AuthorizationEndpoint
}

func (t *TestProviderConfiguration) EndSessionEndpointURL() url.URL {
	u, _ := url.Parse(t.metadata.EndSessionEndpoint)
	return *u
}

func (t *TestProviderConfiguration) Issuer() string {
	return t.metadata.Issuer
}

func (t *TestProviderConfiguration) JwksURI() string {
	return t.metadata.JwksURI
}

func (t *TestProviderConfiguration) TokenEndpoint() string {
	return t.metadata.TokenEndpoint
}

func (t *TestProviderConfiguration) ACRValuesSupported() openidconfig.Supported {
	return t.metadata.ACRValuesSupported
}

func (t *TestProviderConfiguration) UILocalesSupported() openidconfig.Supported {
	return t.metadata.UILocalesSupported
}

func (t *TestProviderConfiguration) Name() string {
	return string(t.cfg.OpenID.Provider)
}

func (t *TestProviderConfiguration) SessionStateRequired() bool {
	return len(t.metadata.CheckSessionIframe) > 0
}

func (t *TestProviderConfiguration) SidClaimRequired() bool {
	return t.metadata.FrontchannelLogoutSupported && t.metadata.FrontchannelLogoutSessionSupported
}

func (t *TestProviderConfiguration) SetAuthorizationEndpoint(url string) {
	t.metadata.AuthorizationEndpoint = url
}

func (t *TestProviderConfiguration) SetCheckSessionIframe(url string) {
	t.metadata.CheckSessionIframe = url
}

func (t *TestProviderConfiguration) SetEndSessionEndpoint(url string) {
	t.metadata.EndSessionEndpoint = url
}

func (t *TestProviderConfiguration) SetFrontchannelLogoutSupported(val bool) {
	t.metadata.FrontchannelLogoutSupported = val
}

func (t *TestProviderConfiguration) SetFrontchannelLogoutSessionSupported(val bool) {
	t.metadata.FrontchannelLogoutSessionSupported = val
}

func (t *TestProviderConfiguration) SetIssuer(url string) {
	t.metadata.Issuer = url
}

func (t *TestProviderConfiguration) SetJwksURI(url string) {
	t.metadata.JwksURI = url
}

func (t *TestProviderConfiguration) SetTokenEndpoint(url string) {
	t.metadata.TokenEndpoint = url
}

func (t *TestProviderConfiguration) WithFrontChannelLogoutSupport() {
	t.SetFrontchannelLogoutSupported(true)
	t.SetFrontchannelLogoutSessionSupported(true)
}

func (t *TestProviderConfiguration) WithCheckSessionIFrameSupport(url string) {
	t.SetCheckSessionIframe(url)
}

func providerConfiguration(cfg *config.Config) *TestProviderConfiguration {
	return &TestProviderConfiguration{
		cfg: cfg,
		metadata: &openidconfig.ProviderMetadata{
			ACRValuesSupported: openidconfig.Supported{"Level3", "Level4"},
			UILocalesSupported: openidconfig.Supported{"nb", "nb", "en", "se"},
		},
	}
}
