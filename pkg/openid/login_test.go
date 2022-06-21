package openid_test

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
)

func TestLogin_URL(t *testing.T) {
	type loginURLTest struct {
		url         string
		extraParams map[string]string
		error       error
	}

	tests := []loginURLTest{
		{
			url: "http://localhost:1234/oauth2/login?level=Level4",
			extraParams: map[string]string{
				"acr_values": "Level4",
			},
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login?level=NoLevel",
			error: openid.InvalidSecurityLevelError,
		},
		{
			url: "http://localhost:1234/oauth2/login?locale=nb",
			extraParams: map[string]string{
				"ui_locales": "nb",
			},
			error: nil,
		},
		{
			url: "http://localhost:1234/oauth2/login?level=Level4&locale=nb",
			extraParams: map[string]string{
				"acr_values": "Level4",
				"ui_locales": "nb",
			},
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login?locale=es",
			error: openid.InvalidLocaleError,
		},
	}

	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			req, err := http.NewRequest("GET", test.url, nil)
			assert.NoError(t, err)

			provider := mock.NewTestProvider()
			provider.OpenIDConfiguration.AuthorizationEndpoint = "https://provider/authorize"
			client := mock.NewClient(provider)
			result, err := client.Login(req)

			if test.error != nil {
				assert.True(t, errors.Is(err, test.error))
			} else {
				assert.NoError(t, err)

				parsed, err := url.Parse(result.AuthCodeURL())
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
				assert.ElementsMatch(t, query["redirect_uri"], []string{provider.ClientConfiguration.CallbackURI})
				assert.ElementsMatch(t, query["scope"], []string{provider.ClientConfiguration.GetScopes().String()})
				assert.ElementsMatch(t, query["state"], []string{result.State()})
				assert.ElementsMatch(t, query["nonce"], []string{result.Nonce()})
				assert.ElementsMatch(t, query["response_mode"], []string{"query"})
				assert.ElementsMatch(t, query["code_challenge"], []string{result.CodeChallenge()})
				assert.ElementsMatch(t, query["code_challenge_method"], []string{"S256"})

				if test.extraParams != nil {
					for key, value := range test.extraParams {
						assert.Contains(t, query, key)
						assert.ElementsMatch(t, query[key], []string{value})
					}
				}
			}
		})
	}
}

func TestLoginURL_WithResourceIndicator(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:1234/oauth2/login", nil)
	assert.NoError(t, err)

	provider := mock.NewTestProvider()
	provider.OpenIDConfiguration.AuthorizationEndpoint = "https://provider/authorize"
	cfg := mock.Config()
	cfg.Loginstatus.Enabled = true
	cfg.Loginstatus.ResourceIndicator = "https://some-resource"
	client := mock.NewClientWithCfg(cfg, provider)
	result, err := client.Login(req)

	assert.NotEmpty(t, result)
	parsed, err := url.Parse(result.AuthCodeURL())
	assert.NoError(t, err)

	query := parsed.Query()
	assert.Contains(t, query, "resource")
	assert.ElementsMatch(t, query["resource"], []string{"https://some-resource"})
}

func TestLoginURLParameter(t *testing.T) {
	for _, test := range []struct {
		name      string
		parameter string
		fallback  string
		supported openid.Supported
		url       string
		expectErr error
		expected  string
	}{
		{
			name:     "no URL parameter should use fallback value",
			url:      "http://localhost:8080/oauth2/login",
			expected: "valid",
		},
		{
			name:     "non-matching URL parameter should be ignored",
			url:      "http://localhost:8080/oauth2/login?other_param=value2",
			expected: "valid",
		},
		{
			name:     "matching URL parameter should take precedence",
			url:      "http://localhost:8080/oauth2/login?param=valid2",
			expected: "valid2",
		},
		{
			name:      "invalid URL parameter value should return error",
			url:       "http://localhost:8080/oauth2/login?param=invalid",
			expectErr: openid.InvalidLoginParameterError,
		},
		{
			name:      "invalid fallback value should return error",
			fallback:  "invalid",
			url:       "http://localhost:8080/oauth2/login",
			expectErr: openid.InvalidLoginParameterError,
		},
		{
			name:      "no supported values should return error",
			url:       "http://localhost:8080/oauth2/login",
			supported: openid.Supported{""},
			expectErr: openid.InvalidLoginParameterError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", test.url, nil)
			assert.NoError(t, err)

			// default test values
			parameter := "param"
			fallback := "valid"
			supported := openid.Supported{"valid", "valid2"}

			if len(test.parameter) > 0 {
				parameter = test.parameter
			}

			if len(test.fallback) > 0 {
				fallback = test.fallback
			}

			if len(test.supported) > 0 {
				supported = test.supported
			}

			val, err := openid.LoginURLParameter(r, parameter, fallback, supported)

			if test.expectErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, val)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
