package openid_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
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

	assert.Equal(t, sub, parsed.GetToken().Subject())
	assert.Equal(t, "some-issuer", parsed.GetToken().Issuer())
	assert.Equal(t, []string{"some-client-id"}, parsed.GetToken().Audience())
	assert.Equal(t, "some-nonce", parsed.GetStringClaimOrEmpty("nonce"))
	assert.Equal(t, iat, parsed.GetToken().IssuedAt())
	assert.Equal(t, exp, parsed.GetToken().Expiration())
	assert.NotEmpty(t, parsed.GetToken().JwtID())
}

func TestIDToken_GetAcrClaim(t *testing.T) {
	idToken, err := makeIDToken(&claims{
		set: map[string]any{
			"acr": "some-acr",
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "some-acr", idToken.GetAcrClaim())
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

			assert.Equal(t, tt.expected, idToken.GetAmrClaim())
		})
	}
}

func TestIDToken_GetSidClaim(t *testing.T) {
	idToken, err := makeIDToken(&claims{
		set: map[string]any{
			"sid": "some-sid",
		},
	})
	require.NoError(t, err)

	sid, err := idToken.GetSidClaim()
	assert.NoError(t, err)
	assert.Equal(t, "some-sid", sid)
}

func TestIDToken_Validate(t *testing.T) {
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
			expectErr: `"sub" not satisfied: required claim not found`,
		},
		{
			name: "missing exp",
			claims: &claims{
				remove: []string{"exp"},
			},
			expectErr: `"exp" not satisfied: required claim not found`,
		},
		{
			name: "missing iat",
			claims: &claims{
				remove: []string{"iat"},
			},
			expectErr: `"iat" not satisfied: required claim not found`,
		},
		{
			name: "missing iss",
			claims: &claims{
				remove: []string{"iss"},
			},
			expectErr: `"iss" not satisfied: required claim not found`,
		},
		{
			name: "issuer mismatch",
			claims: &claims{
				set: map[string]any{
					"iss": "https://some-other-issuer",
				},
			},
			expectErr: `"iss" not satisfied: values do not match`,
		},
		{
			name: "missing aud",
			claims: &claims{
				remove: []string{"aud"},
			},
			expectErr: `"aud" not satisfied: required claim not found`,
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
			expectErr: `"nonce" not satisfied: claim "nonce" does not exist`,
		},
		{
			name: "nonce mismatch",
			claims: &claims{
				set: map[string]any{
					"nonce": "invalid-nonce",
				},
			},
			expectErr: `"nonce" not satisfied: values do not match`,
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
			expectErr:  `"sid" not satisfied: required claim not found`,
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
			cfg := mock.Config()
			cfg.OpenID.ACRValues = ""
			cfg.OpenID.ClientID = "some-client-id"
			cfg.OpenID.Audiences = []string{"trusted-id-1", "trusted-id-2"}

			if tt.requireAcr {
				cfg.OpenID.ACRValues = "some-acr"
			}

			openidcfg := mock.NewTestConfiguration(cfg)
			openidcfg.TestProvider.SetIssuer("https://some-issuer")
			cookie := &openid.LoginCookie{
				Nonce: "some-nonce",
			}
			c := &claims{
				set: map[string]any{
					"aud": openidcfg.Client().ClientID(),
					"iss": openidcfg.Provider().Issuer(),
				},
				remove: []string{},
			}

			if tt.claims != nil {
				if tt.claims.set != nil {
					for k, v := range tt.claims.set {
						c.set[k] = v
					}
				}
				if len(tt.claims.remove) > 0 {
					c.remove = append(c.remove, tt.claims.remove...)
				}
			}

			if tt.requireSid {
				openidcfg.TestProvider.WithFrontChannelLogoutSupport() // sid claim is required
				if _, ok := c.set["sid"]; !ok {
					c.set["sid"] = "some-sid"
				}
			}

			if tt.requireAcr {
				cookie.Acr = "some-acr"
				if _, ok := c.set["acr"]; !ok {
					c.set["acr"] = "some-acr"
				}
			}

			idToken, err := makeIDToken(c)
			require.NoError(t, err)

			err = idToken.Validate(openidcfg, cookie)

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

	jws, err := jwt.Sign(idToken, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return nil, fmt.Errorf("signing token: %w", err)
	}

	return openid.ParseIDToken(string(jws), jwks.Public)
}
