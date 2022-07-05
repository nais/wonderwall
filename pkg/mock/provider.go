package mock

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/crypto"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

type TestProvider struct {
	OpenIDConfiguration *openidconfig.Provider
	JwksPair            *crypto.JwkSet
}

func (p TestProvider) GetOpenIDConfiguration() *openidconfig.Provider {
	return p.OpenIDConfiguration
}

func (p TestProvider) GetPublicJwkSet(_ context.Context) (*jwk.Set, error) {
	return &p.JwksPair.Public, nil
}

func (p TestProvider) RefreshPublicJwkSet(_ context.Context) (*jwk.Set, error) {
	return &p.JwksPair.Public, nil
}

func (p TestProvider) PrivateJwkSet() *jwk.Set {
	return &p.JwksPair.Private
}

func (p TestProvider) WithFrontChannelLogoutSupport() TestProvider {
	p.OpenIDConfiguration.FrontchannelLogoutSupported = true
	p.OpenIDConfiguration.FrontchannelLogoutSessionSupported = true
	return p
}

func (p TestProvider) WithCheckSessionIFrameSupport(url string) TestProvider {
	p.OpenIDConfiguration.CheckSessionIframe = url
	return p
}

func newTestProvider(cfg Configuration) TestProvider {
	jwksPair, err := crypto.NewJwkSet()
	if err != nil {
		log.Fatal(err)
	}

	return TestProvider{
		OpenIDConfiguration: cfg.ProviderConfig,
		JwksPair:            jwksPair,
	}
}

func providerConfiguration() *openidconfig.Provider {
	return &openidconfig.Provider{
		ACRValuesSupported: openidconfig.Supported{"Level3", "Level4"},
		UILocalesSupported: openidconfig.Supported{"nb", "nb", "en", "se"},
	}
}
