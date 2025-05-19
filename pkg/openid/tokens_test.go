package openid_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

var jwks *crypto.JwkSet

func TestMain(m *testing.M) {
	var err error
	jwks, err = crypto.NewJwkSet()
	if err != nil {
		log.Fatalf("creating jwk set: %+v", err)
	}

	m.Run()
}

func TestParseIDToken(t *testing.T) {
	iat := time.Now().Truncate(time.Second).UTC()
	exp := iat.Add(5 * time.Second)
	sub := uuid.New().String()

	parsed, err := makeIDToken(&claims{
		set: map[string]any{
			"sub": sub,
			"iat": iat.Unix(),
			"exp": exp.Unix(),
		},
	})
	require.NoError(t, err)

	actualSub, ok := parsed.Subject()
	assert.True(t, ok)
	assert.Equal(t, sub, actualSub)

	actualIss, ok := parsed.Issuer()
	assert.True(t, ok)
	assert.Equal(t, "some-issuer", actualIss)

	actualAud, ok := parsed.Audience()
	assert.True(t, ok)
	assert.Equal(t, []string{"some-client-id"}, actualAud)

	assert.Equal(t, "some-nonce", parsed.StringClaimOrEmpty("nonce"))

	actualIat, ok := parsed.IssuedAt()
	assert.True(t, ok)
	assert.Equal(t, iat, actualIat)

	actualExp, ok := parsed.Expiration()
	assert.True(t, ok)
	assert.Equal(t, exp, actualExp)

	actualJti, ok := parsed.JwtID()
	assert.True(t, ok)
	assert.NotEmpty(t, actualJti)
}

func TestIDToken_GetAcrClaim(t *testing.T) {
	idToken, err := makeIDToken(&claims{
		set: map[string]any{
			"acr": "some-acr",
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "some-acr", idToken.Acr())
}

func TestIDToken_GetAmrClaim(t *testing.T) {
	for _, tt := range []struct {
		name     string
		amr      any
		expected string
	}{
		{
			name:     "amr is a string",
			amr:      "some-amr",
			expected: "some-amr",
		},
		{
			name:     "amr is a string array",
			amr:      []string{"some-amr-array"},
			expected: "some-amr-array",
		},
		{
			name:     "amr is a string array with multiple values",
			amr:      []string{"some-amr-1", "some-amr-2"},
			expected: "some-amr-1,some-amr-2",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			idToken, err := makeIDToken(&claims{
				set: map[string]any{
					"amr": tt.amr,
				},
			})
			require.NoError(t, err)

			assert.Equal(t, tt.expected, idToken.Amr())
		})
	}
}

func TestIDToken_GetAuthTimeClaim(t *testing.T) {
	idToken, err := makeIDToken(&claims{
		set: map[string]any{
			"auth_time": time.Now().Unix(),
		},
	})
	require.NoError(t, err)
	assert.NotZero(t, idToken.AuthTime())
}

func TestIDToken_GetLocaleClaim(t *testing.T) {
	idToken, err := makeIDToken(&claims{
		set: map[string]any{
			"locale": "some-locale",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "some-locale", idToken.Locale())
}

func TestIDToken_GetOidClaim(t *testing.T) {
	idToken, err := makeIDToken(&claims{
		set: map[string]any{
			"oid": "some-oid",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "some-oid", idToken.Oid())
}

func TestIDToken_GetSidClaim(t *testing.T) {
	idToken, err := makeIDToken(&claims{
		set: map[string]any{
			"sid": "some-sid",
		},
	})
	require.NoError(t, err)

	sid, err := idToken.Sid()
	assert.NoError(t, err)
	assert.Equal(t, "some-sid", sid)
}

func TestIDToken_Validate(t *testing.T) {
	defaultConfig := func() *config.Config {
		cfg := mock.Config()
		cfg.OpenID.ACRValues = ""
		cfg.OpenID.ClientID = "some-client-id"
		cfg.OpenID.Audiences = []string{"trusted-id-1", "trusted-id-2"}

		return cfg
	}

	defaultOpenIdConfig := func(cfg *config.Config) *mock.TestConfiguration {
		openidcfg := mock.NewTestConfiguration(cfg)
		openidcfg.TestProvider.SetIssuer("https://some-issuer")

		return openidcfg
	}

	defaultClaims := func(cfg openidconfig.Config) *claims {
		return &claims{
			set: map[string]any{
				"aud": cfg.Client().ClientID(),
				"iss": cfg.Provider().Issuer(),
			},
			remove: []string{},
		}
	}

	defaultCookie := func() *openid.LoginCookie {
		return &openid.LoginCookie{
			Nonce: "some-nonce",
		}
	}

	for _, tt := range []struct {
		name       string
		claims     *claims
		requireAcr bool
		requireSid bool
		expectErr  string
	}{
		{
			name: "happy path",
		},
		{
			name: "missing sub",
			claims: &claims{
				remove: []string{"sub"},
			},
			expectErr: `required claim "sub" is missing`,
		},
		{
			name: "missing exp",
			claims: &claims{
				remove: []string{"exp"},
			},
			expectErr: `required claim "exp" is missing`,
		},
		{
			name: "missing iat",
			claims: &claims{
				remove: []string{"iat"},
			},
			expectErr: `required claim "iat" is missing`,
		},
		{
			name: "missing iss",
			claims: &claims{
				remove: []string{"iss"},
			},
			expectErr: `required claim "iss" is missing`,
		},
		{
			name: "iat is in the future",
			claims: &claims{
				set: map[string]any{
					"iat": time.Now().Add(openid.AcceptableSkew + 5*time.Second).Unix(),
				},
			},
			expectErr: `"iat" not satisfied`,
		},
		{
			name: "exp is in the past",
			claims: &claims{
				set: map[string]any{
					"exp": time.Now().Add(-openid.AcceptableSkew - 5*time.Second).Unix(),
				},
			},
			expectErr: `"exp" not satisfied`,
		},
		{
			name: "nbf is in the future",
			claims: &claims{
				set: map[string]any{
					"nbf": time.Now().Add(openid.AcceptableSkew + 5*time.Second).Unix(),
				},
			},
			expectErr: `"nbf" not satisfied`,
		},
		{
			name: "issuer mismatch",
			claims: &claims{
				set: map[string]any{
					"iss": "https://some-other-issuer",
				},
			},
			expectErr: `claim "iss" does not have the expected value`,
		},
		{
			name: "missing aud",
			claims: &claims{
				remove: []string{"aud"},
			},
			expectErr: `required claim "aud" is missing`,
		},
		{
			name: "audience mismatch",
			claims: &claims{
				set: map[string]any{
					"aud": "not-client-id",
				},
			},
			expectErr: `"aud" not satisfied`,
		},
		{
			name: "multiple audiences, missing client_id",
			claims: &claims{
				set: map[string]any{
					"aud": []string{"not-client-id", "trusted-id-1"},
				},
			},
			expectErr: `"aud" not satisfied`,
		},
		{
			name: "multiple audiences, all trusted",
			claims: &claims{
				set: map[string]any{
					"aud": []string{"some-client-id", "trusted-id-1", "trusted-id-2"},
				},
			},
		},
		{
			name: "multiple audiences, has untrusted audiences",
			claims: &claims{
				set: map[string]any{
					"aud": []string{"some-client-id", "trusted-id-1", "trusted-id-2", "untrusted-id-1", "untrusted-id-2"},
				},
			},
			expectErr: `'aud' not satisfied, untrusted audience(s) found: ["untrusted-id-1" "untrusted-id-2"]`,
		},
		{
			name: "missing nonce",
			claims: &claims{
				remove: []string{"nonce"},
			},
			expectErr: `claim "nonce" does not exist`,
		},
		{
			name: "nonce mismatch",
			claims: &claims{
				set: map[string]any{
					"nonce": "invalid-nonce",
				},
			},
			expectErr: `claim "nonce" does not have the expected value`,
		},
		{
			name:       "sid required",
			requireSid: true,
		},
		{
			name: "sid required, missing sid",
			claims: &claims{
				remove: []string{"sid"},
			},
			requireSid: true,
			expectErr:  `required claim "sid" is missing`,
		},
		{
			name:       "acr required",
			requireAcr: true,
		},
		{
			name: "acr required, missing acr",
			claims: &claims{
				remove: []string{"acr"},
			},
			requireAcr: true,
			expectErr:  `invalid acr: got "", expected "some-acr"`,
		},
		{
			name: "acr required, acr mismatch",
			claims: &claims{
				set: map[string]any{
					"acr": "mismatch",
				},
			},
			requireAcr: true,
			expectErr:  `invalid acr: got "mismatch", expected "some-acr"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			openidcfg := defaultOpenIdConfig(cfg)
			cookie := defaultCookie()

			c := defaultClaims(openidcfg)
			c.merge(tt.claims)

			if tt.requireSid {
				openidcfg.TestProvider.WithFrontChannelLogoutSupport() // sid claim is required
				c.setIfUnset("sid", "some-sid")
			}

			if tt.requireAcr {
				cfg.OpenID.ACRValues = "some-acr"
				cookie.Acr = "some-acr"
				c.setIfUnset("acr", "some-acr")
			}

			idToken, err := makeIDToken(c)
			require.NoError(t, err)

			err = idToken.Validate(openidcfg, cookie, &jwks.Public)
			if tt.expectErr != "" {
				assert.ErrorContains(t, err, tt.expectErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type claims struct {
	set    map[string]any
	remove []string
}

func (in *claims) setIfUnset(key, value string) {
	if _, ok := in.set[key]; !ok {
		in.set[key] = value
	}
}

func (in *claims) merge(other *claims) {
	if other == nil {
		return
	}

	if other.set != nil {
		for k, v := range other.set {
			in.set[k] = v
		}
	}

	if len(other.remove) > 0 {
		in.remove = append(in.remove, other.remove...)
	}
}

func makeIDToken(claims *claims) (*openid.IDToken, error) {
	iat := time.Now().Truncate(time.Second).UTC()
	exp := iat.Add(5 * time.Second)
	sub := uuid.New().String()

	idToken := jwt.New()
	idToken.Set("sub", sub)
	idToken.Set("iss", "some-issuer")
	idToken.Set("aud", "some-client-id")
	idToken.Set("nonce", "some-nonce")
	idToken.Set("iat", iat.Unix())
	idToken.Set("exp", exp.Unix())
	idToken.Set("jti", uuid.NewString())

	for claim, claimValue := range claims.set {
		idToken.Set(claim, claimValue)
	}

	for _, claim := range claims.remove {
		idToken.Remove(claim)
	}

	key, ok := jwks.Private.Key(0)
	if !ok {
		return nil, fmt.Errorf("no private key found at index 0")
	}

	jws, err := jwt.Sign(idToken, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return nil, fmt.Errorf("signing token: %w", err)
	}

	return openid.ParseIDToken(string(jws))
}
