package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func TestProviderMetadata_Validate(t *testing.T) {
	metadata := &openidconfig.ProviderMetadata{
		ACRValuesSupported: openidconfig.Supported{"idporten-loa-substantial", "idporten-loa-high"},
		UILocalesSupported: openidconfig.Supported{"nb", "nb", "en", "se"},
	}

	for _, tt := range []struct {
		name, acr, locale string
		assertion         assert.ErrorAssertionFunc
	}{
		{"happy path", "idporten-loa-high", "nb", assert.NoError},
		{"invalid acr", "Level5", "nb", assert.Error},
		{"invalid locale", "idporten-loa-high", "de", assert.Error},
		{"has acr translation for Level4", "Level4", "nb", assert.NoError},
		{"has acr translation for Level3", "Level3", "nb", assert.NoError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mock.Config()
			cfg.OpenID.ACRValues = tt.acr
			cfg.OpenID.UILocales = tt.locale

			err := metadata.Validate(cfg.OpenID)
			tt.assertion(t, err)
		})
	}
}
