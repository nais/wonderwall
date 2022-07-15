package client_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestLogoutFrontchannel_Sid(t *testing.T) {
	t.Run("missing sid parameter in request", func(t *testing.T) {
		url := "http://localhost/oauth2/logout/frontchannel"
		lf := newLogoutFrontchannel(url)

		assert.Empty(t, lf.Sid())
		assert.True(t, lf.MissingSidParameter())
	})

	t.Run("has sid parameter in request", func(t *testing.T) {
		url := "http://localhost/oauth2/logout/frontchannel?sid=some-session-id"
		lf := newLogoutFrontchannel(url)

		assert.Equal(t, "some-session-id", lf.Sid())
		assert.False(t, lf.MissingSidParameter())
	})
}

func newLogoutFrontchannel(url string) client.LogoutFrontchannel {
	req := httptest.NewRequest("GET", url, nil)
	return newTestClient().LogoutFrontchannel(req)
}
