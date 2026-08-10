package config_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/config"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/stretchr/testify/require"
)

func TestNewClientConfigRequiresClientJWKAlgorithm(t *testing.T) {
	key, err := crypto.NewJwk()
	require.NoError(t, err)

	rawKey, err := json.Marshal(key)
	require.NoError(t, err)

	var keyFields map[string]any
	require.NoError(t, json.Unmarshal(rawKey, &keyFields))

	for _, tt := range []struct {
		name       string
		removeAlg  bool
		wantConfig bool
	}{
		{name: "algorithm is present", wantConfig: true},
		{name: "algorithm is missing", removeAlg: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fields := make(map[string]any, len(keyFields))
			for name, value := range keyFields {
				fields[name] = value
			}
			if tt.removeAlg {
				delete(fields, "alg")
			}

			clientJWK, err := json.Marshal(fields)
			require.NoError(t, err)

			cfg := &config.Config{OpenID: config.OpenID{
				ClientID:     "client-id",
				ClientJWK:    string(clientJWK),
				Provider:     config.ProviderOpenID,
				WellKnownURL: "https://issuer.example/.well-known/openid-configuration",
			}}

			client, err := openidconfig.NewClientConfig(cfg)
			if tt.wantConfig {
				require.NoError(t, err)
				require.NotNil(t, client)
				require.Equal(t, jwa.RS256(), client.ClientJWKAlgorithm())
				return
			}

			require.ErrorContains(t, err, "client JWK is missing required")
		})
	}
}
