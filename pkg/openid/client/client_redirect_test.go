package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/pkg/mock"
)

// The token and pushed authorization endpoints receive client credentials, so a redirect
// must not be followed; doing so would forward the credentials to another host.
func TestClient_RefusesRedirect(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	openidConfig := mock.NewTestConfiguration(mock.Config())
	openidConfig.TestProvider.SetTokenEndpoint(redirector.URL)

	_, err := newTestClientWithConfig(openidConfig).
		RefreshGrant(context.Background(), "some-refresh-token", "", "")

	require.Error(t, err)
	assert.ErrorContains(t, err, "refusing to follow redirect")
	assert.False(t, redirected, "the redirect target must not be reached")
}
