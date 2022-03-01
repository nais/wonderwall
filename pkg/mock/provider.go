package mock

import (
	"context"

	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/clients"
)

type TestProvider struct {
	ClientConfiguration *TestClientConfiguration
	OpenIDConfiguration *openid.Configuration
	JwksPair            *crypto.JwkSet
}

func (p TestProvider) GetClientConfiguration() clients.Configuration {
	return p.ClientConfiguration
}

func (p TestProvider) GetOpenIDConfiguration() *openid.Configuration {
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

func NewTestProvider() TestProvider {
	jwksPair, err := crypto.NewJwkSet()
	if err != nil {
		log.Fatal(err)
	}

	clientCfg := clientConfiguration()
	provider := TestProvider{
		ClientConfiguration: &clientCfg,
		OpenIDConfiguration: &openid.Configuration{
			ACRValuesSupported: openid.Supported{"Level3", "Level4"},
			UILocalesSupported: openid.Supported{"nb", "nb", "en", "se"},
		},
		JwksPair: jwksPair,
	}

	return provider
}
