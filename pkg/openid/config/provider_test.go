package config_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/pkg/mock"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func TestProviderMetadata_Validate(t *testing.T) {
	metadata := &openidconfig.ProviderMetadata{
		ACRValuesSupported:               openidconfig.Supported{"idporten-loa-substantial", "idporten-loa-high"},
		UILocalesSupported:               openidconfig.Supported{"nb", "nb", "en", "se"},
		IDTokenSigningAlgValuesSupported: openidconfig.Supported{"RS256"},
	}

	for _, tt := range []struct {
		name      string
		config    config.OpenID
		assertion assert.ErrorAssertionFunc
	}{
		{
			name:      "happy path",
			config:    config.OpenID{ACRValues: "idporten-loa-high", UILocales: "nb"},
			assertion: assert.NoError,
		},
		{
			name:      "invalid acr",
			config:    config.OpenID{ACRValues: "Level5"},
			assertion: assert.Error,
		},
		{
			name:      "invalid locale",
			config:    config.OpenID{UILocales: "de"},
			assertion: assert.Error,
		},
		{
			name:      "has acr translation for Level4",
			config:    config.OpenID{ACRValues: "Level4"},
			assertion: assert.NoError,
		},
		{
			name:      "has acr translation for Level3",
			config:    config.OpenID{ACRValues: "Level3"},
			assertion: assert.NoError,
		},
		{
			name:      "invalid signing algorithm",
			config:    config.OpenID{JWKSFallbackAlg: "HS256"},
			assertion: assert.Error,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mock.Config()
			if tt.config.ACRValues != "" {
				cfg.OpenID.ACRValues = tt.config.ACRValues
			}
			if tt.config.UILocales != "" {
				cfg.OpenID.UILocales = tt.config.UILocales
			}
			if tt.config.JWKSFallbackAlg != "" {
				cfg.OpenID.JWKSFallbackAlg = tt.config.JWKSFallbackAlg
			}

			err := metadata.Validate(cfg.OpenID, nil)
			tt.assertion(t, err)
		})
	}
}

func TestProviderMetadata_ValidateClientAssertionSigningAlg(t *testing.T) {
	key, err := crypto.NewJwk()
	require.NoError(t, err)
	algorithm, ok := key.Algorithm()
	require.True(t, ok)

	for _, tt := range []struct {
		name      string
		supported []string
		clientAlg jwa.KeyAlgorithm
		assertion assert.ErrorAssertionFunc
	}{
		{name: "supported", supported: []string{"RS256"}, clientAlg: algorithm, assertion: assert.NoError},
		{name: "unsupported", supported: []string{"PS256"}, clientAlg: algorithm, assertion: func(t assert.TestingT, err error, msgAndArgs ...any) bool {
			return assert.ErrorContains(t, err, "does not support client assertion signing algorithm", msgAndArgs...)
		}},
		{name: "metadata field absent", clientAlg: algorithm, assertion: assert.NoError},
		// client_secret has no assertion alg; PS256 proves the check is skipped, not passed.
		{name: "no client assertion algorithm", supported: []string{"PS256"}, assertion: assert.NoError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// acr and locale pass on empty input, so zeroing them isolates this test.
			cfg := mock.Config()
			cfg.OpenID.ACRValues = ""
			cfg.OpenID.UILocales = ""

			metadata := &openidconfig.ProviderMetadata{
				IDTokenSigningAlgValuesSupported:           openidconfig.Supported{cfg.OpenID.JWKSFallbackAlg},
				TokenEndpointAuthSigningAlgValuesSupported: tt.supported,
			}
			tt.assertion(t, metadata.Validate(cfg.OpenID, tt.clientAlg))
		})
	}
}

func TestNewProviderConfig_NonOK(t *testing.T) {
	for _, statusCode := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
				_, _ = w.Write([]byte("<html>not a metadata document</html>"))
			}))
			defer server.Close()

			cfg := mock.Config()
			cfg.OpenID.WellKnownURL = server.URL

			_, err := openidconfig.NewProviderConfig(context.Background(), cfg, nil)
			require.Error(t, err)
			assert.ErrorContains(t, err, "responded with HTTP")
		})
	}
}

func TestNewProviderConfig_CancelledContext(t *testing.T) {
	cfg := mock.Config()
	cfg.OpenID.WellKnownURL = "http://localhost:0/.well-known/openid-configuration"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := openidconfig.NewProviderConfig(ctx, cfg, nil)
	assert.Error(t, err)
}
