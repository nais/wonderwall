package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenIDValidate(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "requires valid JWKS fallback algorithm",
			cfg:  Config{OpenID: OpenID{JWKSFallbackAlg: "invalid"}},
			want: `invalid JWKS fallback algorithm: "invalid"`,
		},
		{
			name: "requires client JWK",
			cfg:  Config{OpenID: OpenID{DPoP: true, JWKSFallbackAlg: "RS256"}},
			want: `"openid.dpop" requires "openid.client-jwk"`,
		},
		{
			name: "not supported in SSO mode",
			cfg: Config{
				OpenID: OpenID{ClientJWK: `{"alg":"RS256"}`, DPoP: true, JWKSFallbackAlg: "RS256"},
				SSO:    SSO{Enabled: true},
			},
			want: `"openid.dpop" is not supported in SSO mode`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.ErrorContains(t, test.cfg.OpenID.Validate(&test.cfg), test.want)
		})
	}
}
