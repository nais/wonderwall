package client_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestLogoutCallback_ValidateRequest(t *testing.T) {
	t.Run("nil cookie", func(t *testing.T) {
		_, err := newLogoutCallback(t, "http://localhost/oauth2/logout/callback?state=some-state", nil)
		assert.Error(t, err)
	})

	for _, test := range []struct {
		name    string
		url     string
		cookie  *openid.LogoutCookie
		wantErr bool
	}{
		{
			name: "valid request",
			url:  "http://localhost/oauth2/logout/callback?state=some-state",
			cookie: &openid.LogoutCookie{
				State:      "some-state",
				RedirectTo: "http://some-url",
			},
			wantErr: false,
		},
		{
			name: "empty redirect",
			url:  "http://localhost/oauth2/logout/callback?state=some-state",
			cookie: &openid.LogoutCookie{
				State:      "some-state",
				RedirectTo: "",
			},
			wantErr: true,
		},
		{
			name: "empty state",
			url:  "http://localhost/oauth2/logout/callback",
			cookie: &openid.LogoutCookie{
				State:      "some-state",
				RedirectTo: "http://some-url",
			},
			wantErr: true,
		},
		{
			name: "state mismatch",
			url:  "http://localhost/oauth2/logout/callback?state=some-other-state",
			cookie: &openid.LogoutCookie{
				State:      "some-state",
				RedirectTo: "http://some-url",
			},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			lc, err := newLogoutCallback(t, test.url, test.cookie)
			assert.NoError(t, err)

			err = lc.ValidateRequest()
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func newLogoutCallback(t *testing.T, url string, cookie *openid.LogoutCookie) (client.LogoutCallback, error) {
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	return newTestClient().LogoutCallback(req, cookie)
}
