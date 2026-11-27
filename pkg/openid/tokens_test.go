package openid_test

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
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

func TestIDToken_StringClaimErrors(t *testing.T) {
	claims := jwt.New()
	idToken := openid.NewIDToken("", claims)
	_, err := idToken.StringClaim(openid.SidClaim)
	assert.ErrorIs(t, err, jwt.ClaimNotFoundError{})

	require.NoError(t, claims.Set(openid.SidClaim, 123))
	_, err = idToken.StringClaim(openid.SidClaim)
	assert.ErrorIs(t, err, jwt.ClaimTypeMismatchError{})

	_, err = openid.NewIDToken("", nil).StringClaim(openid.SidClaim)
	assert.ErrorContains(t, err, "token is nil")
}

func TestIDToken_Validate(t *testing.T) {
	for _, tt := range []struct {
		name         string
		mutate       func(tok jwt.Token)
		requireAcr   bool
		requireSid   bool
		expectErr    string
		expectJWTErr error
	}{
		{
			name: "happy path",
		},
		{
			name: "missing sub",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("sub")
			},
			expectJWTErr: jwt.MissingRequiredClaimError{Claim: "sub"},
		},
		{
			name: "missing exp",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("exp")
			},
			expectJWTErr: jwt.MissingRequiredClaimError{Claim: "exp"},
		},
		{
			name: "missing iat",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("iat")
			},
			expectJWTErr: jwt.MissingRequiredClaimError{Claim: "iat"},
		},
		{
			name: "missing iss",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("iss")
			},
			expectJWTErr: jwt.MissingRequiredClaimError{Claim: "iss"},
		},
		{
			name: "iat is in the future",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("iat", time.Now().Add(openid.AcceptableSkew+5*time.Second).Unix())
			},
			expectJWTErr: jwt.InvalidIssuedAtError{},
		},
		{
			name: "exp is in the past",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("exp", time.Now().Add(-openid.AcceptableSkew-5*time.Second).Unix())
			},
			expectJWTErr: jwt.TokenExpiredError{},
		},
		{
			name: "nbf is in the future",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("nbf", time.Now().Add(openid.AcceptableSkew+5*time.Second).Unix())
			},
			expectJWTErr: jwt.TokenNotYetValidError{},
		},
		{
			name: "issuer mismatch",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("iss", "https://some-other-issuer")
			},
			expectJWTErr: jwt.InvalidIssuerError{},
		},
		{
			name: "missing aud",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("aud")
			},
			expectJWTErr: jwt.MissingRequiredClaimError{Claim: "aud"},
		},
		{
			name: "audience mismatch",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", "not-client-id")
			},
			expectJWTErr: jwt.InvalidAudienceError{},
		},
		{
			name: "multiple audiences, missing client_id",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", []string{"not-client-id", "trusted-id-1"})
			},
			expectJWTErr: jwt.InvalidAudienceError{},
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
			expectJWTErr: jwt.ClaimValidationError{Claim: "nonce"},
		},
		{
			name: "nonce mismatch",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("nonce", "invalid-nonce")
			},
			expectJWTErr: jwt.ClaimValidationError{Claim: "nonce"},
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
			requireSid:   true,
			expectJWTErr: jwt.MissingRequiredClaimError{Claim: "sid"},
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
			switch expected := tt.expectJWTErr.(type) {
			case jwt.MissingRequiredClaimError:
				var actual jwt.MissingRequiredClaimError
				require.ErrorAs(t, err, &actual)
				assert.Equal(t, expected.Claim, actual.Claim)
			case jwt.ClaimValidationError:
				var actual jwt.ClaimValidationError
				require.ErrorAs(t, err, &actual)
				assert.Equal(t, expected.Claim, actual.Claim)
			case nil:
				if tt.expectErr == "" {
					assert.NoError(t, err)
				} else {
					assert.ErrorContains(t, err, tt.expectErr)
				}
			default:
				assert.ErrorIs(t, err, expected)
			}
		})
	}
}

func TestIDToken_ValidateAlgorithmMatch(t *testing.T) {
	cfg := mock.Config()
	cfg.OpenID.ACRValues = ""
	cfg.OpenID.ClientID = "some-client-id"
	openidcfg := mock.NewTestConfiguration(cfg)
	openidcfg.TestProvider.SetIssuer("https://some-issuer")

	token, err := makeIDToken(nil)
	require.NoError(t, err)
	key, ok := jwks.Private.Key(0)
	require.True(t, ok)
	privateKey, err := jwk.Export[*rsa.PrivateKey](key)
	require.NoError(t, err)
	kid, ok := key.KeyID()
	require.True(t, ok)
	payload := strings.Split(token.Serialized(), ".")[1]

	for _, alg := range []string{"RS256", "RS512"} {
		t.Run(alg, func(t *testing.T) {
			header, err := json.Marshal(map[string]string{"alg": alg, "kid": kid})
			require.NoError(t, err)
			input := base64.RawURLEncoding.EncodeToString(header) + "." + payload
			digest := sha256.Sum256([]byte(input))
			// Sign with RS256 even when the protected header advertises RS512.
			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, stdcrypto.SHA256, digest[:])
			require.NoError(t, err)
			raw := input + "." + base64.RawURLEncoding.EncodeToString(signature)

			parsed, err := openid.ParseIDToken(raw)
			require.NoError(t, err)
			err = parsed.Validate(openidcfg, "", "some-nonce", &jwks.Public)
			if alg == "RS256" {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, jws.VerificationError())
			}
		})
	}
}

func TestValidateRefreshedIDToken(t *testing.T) {
	issuedAt := time.Now().Unix()
	for _, tt := range []struct {
		name         string
		previous     func(tok jwt.Token)
		refreshed    func(tok jwt.Token)
		requireAcr   bool
		expectErr    string
		expectJWTErr error
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
				_ = tok.Set("iat", issuedAt)
			},
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("iat", issuedAt)
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
			expectJWTErr: jwt.InvalidIssuedAtError{},
		},
		{
			name: "exp is in the past",
			refreshed: func(tok jwt.Token) {
				_ = tok.Set("exp", time.Now().Add(-openid.AcceptableSkew-5*time.Second).Unix())
			},
			expectJWTErr: jwt.TokenExpiredError{},
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
			if tt.expectJWTErr != nil {
				assert.ErrorIs(t, err, tt.expectJWTErr)
			} else if tt.expectErr != "" {
				assert.ErrorContains(t, err, tt.expectErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNormalizeTokenType(t *testing.T) {
	assertMismatch := func(t assert.TestingT, err error, msgAndArgs ...any) bool {
		return assert.ErrorIs(t, err, openid.ErrTokenTypeMismatch, msgAndArgs...)
	}

	for _, test := range []struct {
		name        string
		value       string
		dpop        bool
		expected    string
		assertError assert.ErrorAssertionFunc
	}{
		{name: "empty bearer", expected: "Bearer", assertError: assert.NoError},
		{name: "bearer case insensitive", value: "bEaReR", expected: "Bearer", assertError: assert.NoError},
		{name: "dpop case insensitive", value: "dPoP", dpop: true, expected: "DPoP", assertError: assert.NoError},
		{name: "unsupported", value: "Basic", assertError: func(t assert.TestingT, err error, msgAndArgs ...any) bool {
			return assert.ErrorIs(t, err, openid.ErrTokenTypeMismatch, msgAndArgs...) &&
				assert.ErrorContains(t, err, `unsupported token_type "Basic"`, msgAndArgs...)
		}},
		{name: "dpop disabled", value: "DPoP", assertError: assertMismatch},
		{name: "empty with dpop enabled", dpop: true, assertError: assertMismatch},
		{name: "bearer with dpop enabled", value: "Bearer", dpop: true, assertError: assertMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := openid.NormalizeTokenType(test.value, test.dpop)
			test.assertError(t, err)
			assert.Equal(t, test.expected, actual)
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
