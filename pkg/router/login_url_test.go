package router_test

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router"
)

func TestLoginURL(t *testing.T) {
	type loginURLTest struct {
		url   string
		error error
	}

	tests := []loginURLTest{
		{
			url:   "http://localhost:1234/oauth2/login?level=Level4",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login?level=NoLevel",
			error: router.InvalidSecurityLevelError,
		},
		{
			url:   "http://localhost:1234/oauth2/login?locale=nb",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login?level=Level4&locale=nb",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login?locale=es",
			error: router.InvalidLocaleError,
		},
	}

	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			req, err := http.NewRequest("GET", test.url, nil)
			assert.NoError(t, err)

			params, err := openid.GenerateLoginParameters()
			assert.NoError(t, err)

			provider := mock.NewTestProvider()
			provider.OpenIDConfiguration.AuthorizationEndpoint = "https://provider/authorize"
			handler := newHandler(provider)
			result, err := handler.LoginURL(req, params)

			if test.error != nil {
				assert.True(t, errors.Is(err, test.error))
			} else {
				assert.NoError(t, err)

				parsed, err := url.Parse(result)
				assert.NoError(t, err)

				query := parsed.Query()
				assert.Contains(t, query, "response_type")
				assert.Contains(t, query, "client_id")
				assert.Contains(t, query, "redirect_uri")
				assert.Contains(t, query, "scope")
				assert.Contains(t, query, "state")
				assert.Contains(t, query, "nonce")
				assert.Contains(t, query, "response_mode")
				assert.Contains(t, query, "code_challenge")
				assert.Contains(t, query, "code_challenge_method")
				assert.NotContains(t, query, "resource")

				assert.ElementsMatch(t, query["response_type"], []string{"code"})
				assert.ElementsMatch(t, query["client_id"], []string{provider.ClientConfiguration.ClientID})
				assert.ElementsMatch(t, query["redirect_uri"], []string{provider.ClientConfiguration.RedirectURI})
				assert.ElementsMatch(t, query["scope"], []string{provider.ClientConfiguration.GetScopes().String()})
				assert.ElementsMatch(t, query["state"], []string{params.State})
				assert.ElementsMatch(t, query["nonce"], []string{params.Nonce})
				assert.ElementsMatch(t, query["response_mode"], []string{"query"})
				assert.ElementsMatch(t, query["code_challenge"], []string{params.CodeChallenge})
				assert.ElementsMatch(t, query["code_challenge_method"], []string{"S256"})
			}
		})
	}
}

func TestLoginURL_WithResourceIndicator(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:1234/oauth2/login", nil)
	assert.NoError(t, err)

	params, err := openid.GenerateLoginParameters()
	assert.NoError(t, err)

	provider := mock.NewTestProvider()
	provider.OpenIDConfiguration.AuthorizationEndpoint = "https://provider/authorize"
	handler := newHandler(provider)
	handler.Config.Loginstatus.Enabled = true
	handler.Config.Loginstatus.ResourceIndicator = "https://some-resource"
	result, err := handler.LoginURL(req, params)

	assert.NotEmpty(t, result)
	parsed, err := url.Parse(result)
	assert.NoError(t, err)

	query := parsed.Query()
	assert.Contains(t, query, "resource")
	assert.ElementsMatch(t, query["resource"], []string{"https://some-resource"})
}
