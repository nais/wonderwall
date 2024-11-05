package config_test

import (
	"testing"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/stretchr/testify/assert"

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
			config:    config.OpenID{IDTokenSigningAlg: "HS256"},
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
			if tt.config.IDTokenSigningAlg != "" {
				cfg.OpenID.IDTokenSigningAlg = tt.config.IDTokenSigningAlg
			}

			err := metadata.Validate(cfg.OpenID)
			tt.assertion(t, err)
		})
	}
}
