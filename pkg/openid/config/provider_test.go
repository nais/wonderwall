package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func TestProviderMetadata_Validate(t *testing.T) {
	metadata := &openidconfig.ProviderMetadata{
		ACRValuesSupported: openidconfig.Supported{"Level3", "Level4"},
		UILocalesSupported: openidconfig.Supported{"nb", "nb", "en", "se"},
	}

	for _, tt := range []struct {
		name, acr, locale string
		assertion         assert.ErrorAssertionFunc
	}{
		{"happy path", "Level4", "nb", assert.NoError},
		{"invalid acr", "Level5", "nb", assert.Error},
		{"invalid locale", "Level4", "de", assert.Error},
		{"has matching acr translation", "idporten-loa-high", "nb", assert.NoError},
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
