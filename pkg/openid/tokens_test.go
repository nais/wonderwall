package openid_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/internal/crypto"
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

	parsed, err := makeIDToken(func(tok jwt.Token) {
		_ = tok.Set("sub", sub)
		_ = tok.Set("iat", iat.Unix())
		_ = tok.Set("exp", exp.Unix())
	})
	require.NoError(t, err)

	actualSub, ok := parsed.Subject()
	assert.True(t, ok)
	assert.Equal(t, sub, actualSub)

	actualIss, ok := parsed.Issuer()
	assert.True(t, ok)
	assert.Equal(t, "https://some-issuer", actualIss)

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
	idToken, err := makeIDToken(func(tok jwt.Token) {
		_ = tok.Set("acr", "some-acr")
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
			idToken, err := makeIDToken(func(tok jwt.Token) {
				_ = tok.Set("amr", tt.amr)
			})
			require.NoError(t, err)

			assert.Equal(t, tt.expected, idToken.Amr())
		})
	}
}

func TestIDToken_GetAuthTimeClaim(t *testing.T) {
	idToken, err := makeIDToken(func(tok jwt.Token) {
		_ = tok.Set("auth_time", time.Now().Unix())
	})
	require.NoError(t, err)
	assert.NotZero(t, idToken.AuthTime())
}

func TestIDToken_GetLocaleClaim(t *testing.T) {
	idToken, err := makeIDToken(func(tok jwt.Token) {
		_ = tok.Set("locale", "some-locale")
	})
	require.NoError(t, err)
	assert.Equal(t, "some-locale", idToken.Locale())
}

func TestIDToken_GetOidClaim(t *testing.T) {
	idToken, err := makeIDToken(func(tok jwt.Token) {
		_ = tok.Set("oid", "some-oid")
	})
	require.NoError(t, err)
	assert.Equal(t, "some-oid", idToken.Oid())
}

func TestIDToken_GetSidClaim(t *testing.T) {
	idToken, err := makeIDToken(func(tok jwt.Token) {
		_ = tok.Set("sid", "some-sid")
	})
	require.NoError(t, err)

	sid, err := idToken.Sid()
	assert.NoError(t, err)
	assert.Equal(t, "some-sid", sid)
}

func TestIDToken_Validate(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mutate     func(tok jwt.Token)
		requireAcr bool
		requireSid bool
		expectErr  string
	}{
		{
			name: "happy path",
		},
		{
			name: "missing sub",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("sub")
			},
			expectErr: `required claim "sub" is missing`,
		},
		{
			name: "missing exp",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("exp")
			},
			expectErr: `required claim "exp" is missing`,
		},
		{
			name: "missing iat",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("iat")
			},
			expectErr: `required claim "iat" is missing`,
		},
		{
			name: "missing iss",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("iss")
			},
			expectErr: `required claim "iss" is missing`,
		},
		{
			name: "iat is in the future",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("iat", time.Now().Add(openid.AcceptableSkew+5*time.Second).Unix())
			},
			expectErr: `"iat" not satisfied`,
		},
		{
			name: "exp is in the past",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("exp", time.Now().Add(-openid.AcceptableSkew-5*time.Second).Unix())
			},
			expectErr: `"exp" not satisfied`,
		},
		{
			name: "nbf is in the future",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("nbf", time.Now().Add(openid.AcceptableSkew+5*time.Second).Unix())
			},
			expectErr: `"nbf" not satisfied`,
		},
		{
			name: "issuer mismatch",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("iss", "https://some-other-issuer")
			},
			expectErr: `claim "iss" does not have the expected value`,
		},
		{
			name: "missing aud",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("aud")
			},
			expectErr: `required claim "aud" is missing`,
		},
		{
			name: "audience mismatch",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", "not-client-id")
			},
			expectErr: `"aud" not satisfied`,
		},
		{
			name: "multiple audiences, missing client_id",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", []string{"not-client-id", "trusted-id-1"})
			},
			expectErr: `"aud" not satisfied`,
		},
		{
			name: "multiple audiences, all trusted",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", []string{"some-client-id", "trusted-id-1", "trusted-id-2"})
			},
		},
		{
			name: "multiple audiences, has untrusted audiences",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", []string{"some-client-id", "trusted-id-1", "trusted-id-2", "untrusted-id-1", "untrusted-id-2"})
			},
			expectErr: `'aud' not satisfied, untrusted audience(s) found: ["untrusted-id-1" "untrusted-id-2"]`,
		},
		{
			name: "missing nonce",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("nonce")
			},
			expectErr: `claim "nonce" does not exist`,
		},
		{
			name: "nonce mismatch",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("nonce", "invalid-nonce")
			},
			expectErr: `claim "nonce" does not have the expected value`,
		},
		{
			name: "sid required",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("sid", "some-sid")
			},
			requireSid: true,
		},
		{
			name: "sid required, missing sid",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("sid")
			},
			requireSid: true,
			expectErr:  `required claim "sid" is missing`,
		},
		{
			name: "acr expected",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("acr", "some-acr")
			},
			requireAcr: true,
		},
		{
			name: "acr expected, missing acr",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("acr")
			},
			requireAcr: true,
			expectErr:  `invalid acr: got "", expected "some-acr"`,
		},
		{
			name: "acr expected, acr mismatch",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("acr", "mismatch")
			},
			requireAcr: true,
			expectErr:  `invalid acr: got "mismatch", expected "some-acr"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mock.Config()
			cfg.OpenID.ACRValues = ""
			if tt.requireAcr {
				cfg.OpenID.ACRValues = "some-acr"
			}
			cfg.OpenID.Audiences = []string{"trusted-id-1", "trusted-id-2"}
			cfg.OpenID.ClientID = "some-client-id"

			openidcfg := mock.NewTestConfiguration(cfg)
			openidcfg.TestProvider.SetIssuer("https://some-issuer")
			if tt.requireSid {
				openidcfg.TestProvider.WithFrontChannelLogoutSupport()
			}

			// This is the `acr` value requested in the authorization request
			expectedAcr := ""
			if tt.requireAcr {
				expectedAcr = "some-acr"
			}

			idToken, err := makeIDToken(tt.mutate)
			require.NoError(t, err)

			expectedNonce := "some-nonce"
			err = idToken.Validate(openidcfg, expectedAcr, expectedNonce, &jwks.Public)
			if tt.expectErr != "" {
				assert.ErrorContains(t, err, tt.expectErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRefreshedIDToken(t *testing.T) {
	for _, tt := range []struct {
		name       string
		previous   func(tok jwt.Token)
		refreshed  func(tok jwt.Token)
		requireAcr bool
		expectErr  string
	}{
		{
			name: "happy path",
		},
		{
			name: "issuer mismatch",
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("iss", "https://some-other-issuer")
			},
			expectErr: `'iss' claim mismatch`,
		},
		{
			name: "subject mismatch",
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("sub", "some-other-sub")
			},
			expectErr: `'sub' claim mismatch`,
		},
		{
			name: "iat unchanged",
			previous: func(tok jwt.Token) {
				_ = tok.Set("iat", time.Now().Unix())
			},
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("iat", time.Now().Unix())
			},
			expectErr: "'iat' claim in refreshed id_token must be greater than previous id_token",
		},
		{
			name: "audience mismatch",
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("aud", []string{"some-client id", "trusted-id-1"})
			},
			expectErr: `'aud' claim mismatch`,
		},
		{
			name: "auth_time mismatch",
			previous: func(tok jwt.Token) {
				_ = tok.Set("auth_time", time.Now().Unix())
			},
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("auth_time", time.Now().Add(5*time.Second).Unix())
			},
			expectErr: "'auth_time' claim mismatch",
		},
		{
			name: "nonce mismatch",
			previous: func(tok jwt.Token) {
				_ = tok.Set("nonce", "some-nonce")
			},
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("nonce", "some-other-nonce")
			},
			expectErr: "'nonce' claim mismatch",
		},
		{
			name: "acr mismatch",
			previous: func(tok jwt.Token) {
				_ = tok.Set("acr", "some-acr")
			},
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("acr", "some-other-acr")
			},
			requireAcr: true,
			expectErr:  `invalid acr: got "some-other-acr", expected "some-acr"`,
		},
		{
			name: "iat is in the future",
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("iat", time.Now().Add(openid.AcceptableSkew+5*time.Second).Unix())
			},
			expectErr: `"iat" not satisfied`,
		},
		{
			name: "exp is in the past",
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("exp", time.Now().Add(-openid.AcceptableSkew-5*time.Second).Unix())
			},
			expectErr: `"exp" not satisfied`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mock.Config()
			cfg.OpenID.ACRValues = ""
			if tt.requireAcr {
				cfg.OpenID.ACRValues = "some-acr"
			}
			cfg.OpenID.Audiences = []string{"trusted-id-1", "trusted-id-2"}
			cfg.OpenID.ClientID = "some-client-id"

			openidcfg := mock.NewTestConfiguration(cfg)
			openidcfg.TestProvider.SetIssuer("https://some-issuer")

			previousIDToken, err := makeIDToken(func(tok jwt.Token) {
				_ = tok.Set("sub", "some-sub")
				if tt.previous != nil {
					tt.previous(tok)
				}
			})
			require.NoError(t, err)

			prevIat, ok := previousIDToken.IssuedAt()
			require.True(t, ok)
			prevExp, ok := previousIDToken.Expiration()
			require.True(t, ok)
			refreshedIDToken, err := makeIDToken(func(tok jwt.Token) {
				_ = tok.Set("sub", "some-sub")
				_ = tok.Set("iat", prevIat.Add(5*time.Second).Unix())
				_ = tok.Set("exp", prevExp.Add(5*time.Second).Unix())
				if tt.refreshed != nil {
					tt.refreshed(tok)
				}
			})
			require.NoError(t, err)

			expectedAcr := ""
			if acr := previousIDToken.Acr(); acr != "" && tt.requireAcr {
				expectedAcr = acr
			}

			err = openid.ValidateRefreshedIDToken(openidcfg,
				previousIDToken.Serialized(),
				refreshedIDToken.Serialized(),
				expectedAcr,
				&jwks.Public)
			if tt.expectErr != "" {
				assert.ErrorContains(t, err, tt.expectErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func makeIDToken(mutate func(tok jwt.Token)) (*openid.IDToken, error) {
	iat := time.Now().Truncate(time.Second).UTC()
	exp := iat.Add(5 * time.Second)
	sub := uuid.New().String()

	tok := jwt.New()
	_ = tok.Set("sub", sub)
	_ = tok.Set("iss", "https://some-issuer")
	_ = tok.Set("aud", "some-client-id")
	_ = tok.Set("nonce", "some-nonce")
	_ = tok.Set("iat", iat.Unix())
	_ = tok.Set("exp", exp.Unix())
	_ = tok.Set("jti", uuid.NewString())

	if mutate != nil {
		mutate(tok)
	}

	key, ok := jwks.Private.Key(0)
	if !ok {
		return nil, fmt.Errorf("no private key found at index 0")
	}

	alg, ok := key.Algorithm()
	if !ok {
		return nil, fmt.Errorf("no algorithm found for key")
	}

	jws, err := jwt.Sign(tok, jwt.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("signing token: %w", err)
	}

	return openid.ParseIDToken(string(jws))
}
