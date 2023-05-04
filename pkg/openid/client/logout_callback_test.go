package client_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/url"
)

func TestLogoutCallback_PostLogoutRedirectURI(t *testing.T) {
	const defaultState = "some-state"
	const defaultRedirectURI = "http://some-fancy-logout-page"

	for _, tt := range []struct {
		name            string
		emptyDefaultURI bool
		cookie          *openid.LogoutCookie
		expected        string
	}{
		{
			name:     "happy path",
			expected: defaultRedirectURI,
		},
		{
			name:            "empty default uri",
			emptyDefaultURI: true,
			expected:        mock.Ingress,
		},
		{
			name: "state mismatch",
			cookie: &openid.LogoutCookie{
				State: "some-other-state",
			},
			expected: defaultRedirectURI,
		},
		{
			name: "happy path, redirect in cookie",
			cookie: &openid.LogoutCookie{
				State:      defaultState,
				RedirectTo: "http://wonderwall/some/path",
			},
			expected: "http://wonderwall/some/path",
		},
		{
			name: "empty redirect in cookie",
			cookie: &openid.LogoutCookie{
				State:      defaultState,
				RedirectTo: "",
			},
			expected: defaultRedirectURI,
		},
		{
			name: "state mismatch, with redirect in cookie",
			cookie: &openid.LogoutCookie{
				State:      "some-other-state",
				RedirectTo: "http://wonderwall/some/path",
			},
			expected: defaultRedirectURI,
		},
		{
			name: "invalid redirect in cookie",
			cookie: &openid.LogoutCookie{
				State:      defaultState,
				RedirectTo: "http://not-wonderwall/some/path",
			},
			expected: defaultRedirectURI,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mock.Config()
			cfg.OpenID.PostLogoutRedirectURI = defaultRedirectURI

			if tt.emptyDefaultURI {
				cfg.OpenID.PostLogoutRedirectURI = ""
			}

			lc := newLogoutCallback(cfg, defaultState, tt.cookie)

			uri := lc.PostLogoutRedirectURI()
			assert.NotEmpty(t, uri)
			assert.Equal(t, tt.expected, uri)
		})
	}
}

func newLogoutCallback(cfg *config.Config, state string, cookie *openid.LogoutCookie) *client.LogoutCallback {
	openidCfg := mock.NewTestConfiguration(cfg)
	ingresses := mock.Ingresses(cfg)
	validator := url.NewAbsoluteValidator(ingresses.Hosts())
	req := mock.NewGetRequest(mock.Ingress+"/oauth2/logout/callback?state="+state, ingresses)
	return newTestClientWithConfig(openidCfg).LogoutCallback(req, cookie, validator)
}
