package config_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/pkg/mock"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func TestNewProviderConfig_NonOK(t *testing.T) {
	for _, statusCode := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(statusCode)
			_, _ = w.Write([]byte("<html>not a metadata document</html>"))
		}))
		defer server.Close()

		cfg := mock.Config()
		cfg.OpenID.WellKnownURL = server.URL

		_, err := openidconfig.NewProviderConfig(context.Background(), cfg)
		require.Error(t, err)
		assert.ErrorContains(t, err, "responded with HTTP")
	}
}

func TestNewProviderConfig_CancelledContext(t *testing.T) {
	cfg := mock.Config()
	cfg.OpenID.WellKnownURL = "http://localhost:0/.well-known/openid-configuration"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := openidconfig.NewProviderConfig(ctx, cfg)
	assert.Error(t, err)
}
