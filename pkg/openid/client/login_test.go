package client_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/openid/config"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

func TestLogin_URL(t *testing.T) {
	type loginURLTest struct {
		name       string
		url        string
		wantParams map[string]string
		metadata   *config.ProviderMetadata
		error      error
	}

	tests := []loginURLTest{
		{
			name:  "happy path",
			url:   mock.Ingress + "/oauth2/login",
			error: nil,
		},
		{
			name: "happy path with level",
			url:  mock.Ingress + "/oauth2/login?level=Level3",
			wantParams: map[string]string{
				"acr_values": "Level3",
			},
			error: nil,
		},
		{
			name: "happy path with locale",
			url:  mock.Ingress + "/oauth2/login?locale=nb",
			wantParams: map[string]string{
				"ui_locales": "nb",
			},
			error: nil,
		},
		{
			name: "happy path with prompt",
			url:  mock.Ingress + "/oauth2/login?prompt=login",
			wantParams: map[string]string{
				"prompt":  "login",
				"max_age": "0",
			},
			error: nil,
		},
		{
			name: "happy path with both locale and level",
			url:  mock.Ingress + "/oauth2/login?level=Level3&locale=nb",
			wantParams: map[string]string{
				"acr_values": "Level3",
				"ui_locales": "nb",
			},
			error: nil,
		},
		{
			name:  "invalid level",
			url:   mock.Ingress + "/oauth2/login?level=NoLevel",
			error: client.ErrInvalidSecurityLevel,
		},
		{
			name:  "invalid locale",
			url:   mock.Ingress + "/oauth2/login?locale=es",
			error: client.ErrInvalidLocale,
		},
		{
			name:  "invalid prompt",
			url:   mock.Ingress + "/oauth2/login?prompt=invalid",
			error: client.ErrInvalidPrompt,
		},
		{
			name: "level idporten-loa-substantial should translate to Level3 for old IDP",
			url:  mock.Ingress + "/oauth2/login?level=idporten-loa-substantial",
			wantParams: map[string]string{
				"acr_values": "Level3",
			},
			error: nil,
		},
		{
			name: "level idporten-loa-high should translate to Level4 for old IDP",
			url:  mock.Ingress + "/oauth2/login?level=idporten-loa-high",
			wantParams: map[string]string{
				"acr_values": "Level4",
			},
			error: nil,
		},
		{
			name: "level Level3 should translate to idporten-loa-substantial for new IDP",
			url:  mock.Ingress + "/oauth2/login?level=Level3",
			wantParams: map[string]string{
				"acr_values": "idporten-loa-substantial",
			},
			metadata: &config.ProviderMetadata{
				ACRValuesSupported: config.Supported{"idporten-loa-substantial", "idporten-loa-high"},
				UILocalesSupported: config.Supported{"nb", "nb", "en", "se"},
			},
			error: nil,
		},
		{
			name: "level Level4 should translate to idporten-loa-high for new IDP",
			url:  mock.Ingress + "/oauth2/login?level=Level4",
			wantParams: map[string]string{
				"acr_values": "idporten-loa-high",
			},
			metadata: &config.ProviderMetadata{
				ACRValuesSupported: config.Supported{"idporten-loa-substantial", "idporten-loa-high"},
				UILocalesSupported: config.Supported{"nb", "nb", "en", "se"},
			},
			error: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := mock.Config()
			openidConfig := mock.NewTestConfiguration(cfg)
			ingresses := mock.Ingresses(cfg)

			if test.metadata != nil {
				openidConfig.TestProvider.Metadata = test.metadata
			}

			c := client.NewClient(openidConfig, nil)

			req := mock.NewGetRequest(test.url, ingresses)
			result, err := c.Login(req)

			if test.error != nil {
				assert.True(t, errors.Is(err, test.error))
			} else {
				require.NoError(t, err)

				parsed, err := url.Parse(result.AuthCodeURL)
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

				callbackURL, err := urlpkg.LoginCallback(req)
				assert.NoError(t, err)

				assert.ElementsMatch(t, query["response_type"], []string{"code"})
				assert.ElementsMatch(t, query["client_id"], []string{openidConfig.Client().ClientID()})
				assert.ElementsMatch(t, query["redirect_uri"], []string{callbackURL})
				assert.ElementsMatch(t, query["scope"], []string{openidConfig.Client().Scopes().String()})
				assert.ElementsMatch(t, query["state"], []string{result.State})
				assert.ElementsMatch(t, query["nonce"], []string{result.Nonce})
				assert.ElementsMatch(t, query["response_mode"], []string{"query"})
				assert.ElementsMatch(t, query["code_challenge_method"], []string{"S256"})
				assert.ElementsMatch(t, query["code_challenge"], []string{oauth2.S256ChallengeFromVerifier(result.CodeVerifier)})

				if test.wantParams != nil {
					for key, value := range test.wantParams {
						assert.Contains(t, query, key)
						assert.ElementsMatch(t, query[key], []string{value})
					}
				} else {
					assert.Contains(t, query, "acr_values")
					assert.Contains(t, query, "ui_locales")
					assert.ElementsMatch(t, query["acr_values"], []string{openidConfig.Client().ACRValues()})
					assert.ElementsMatch(t, query["ui_locales"], []string{openidConfig.Client().UILocales()})
				}
			}
		})
	}
}

func TestLoginURL_WithResourceIndicator(t *testing.T) {
	cfg := mock.Config()
	cfg.OpenID.ResourceIndicator = "https://some-resource"

	openidConfig := mock.NewTestConfiguration(cfg)
	openidConfig.TestProvider.SetAuthorizationEndpoint("https://provider/authorize")

	c := client.NewClient(openidConfig, nil)
	ingresses := mock.Ingresses(cfg)

	req := mock.NewGetRequest(mock.Ingress+"/oauth2/login", ingresses)

	result, err := c.Login(req)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	parsed, err := url.Parse(result.AuthCodeURL)
	assert.NoError(t, err)

	query := parsed.Query()
	assert.Contains(t, query, "resource")
	assert.ElementsMatch(t, query["resource"], []string{"https://some-resource"})
}
