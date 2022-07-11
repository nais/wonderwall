package client_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestLogoutFrontchannel_Sid(t *testing.T) {
	t.Run("missing sid parameter in request", func(t *testing.T) {
		url := "http://localhost/oauth2/logout/frontchannel"
		lf := newLogoutFrontchannel(t, url)

		assert.Empty(t, lf.Sid())
		assert.True(t, lf.MissingSidParameter())
	})

	t.Run("has sid parameter in request", func(t *testing.T) {
		url := "http://localhost/oauth2/logout/frontchannel?sid=some-session-id"
		lf := newLogoutFrontchannel(t, url)

		assert.Equal(t, "some-session-id", lf.Sid())
		assert.False(t, lf.MissingSidParameter())
	})
}

func newLogoutFrontchannel(t *testing.T, url string) client.LogoutFrontchannel {
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	return newTestClient().LogoutFrontchannel(req)
}
