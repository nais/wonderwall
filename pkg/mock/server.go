package mock

import (
	"net/http/httptest"
)

func IdentityProviderServer() (*httptest.Server, TestProvider) {
	provider := NewTestProvider()
	handler := newIdentityProviderHandler(provider)
	router := identityProviderRouter(handler)
	server := httptest.NewServer(router)

	provider.OpenIDConfiguration.Issuer = server.URL
	provider.OpenIDConfiguration.JwksURI = server.URL + "/jwks"
	provider.OpenIDConfiguration.AuthorizationEndpoint = server.URL + "/authorize"
	provider.OpenIDConfiguration.TokenEndpoint = server.URL + "/token"
	provider.OpenIDConfiguration.EndSessionEndpoint = server.URL + "/endsession"

	return server, provider
}
