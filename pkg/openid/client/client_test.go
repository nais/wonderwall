package client_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestClientAuthenticationAssertion(t *testing.T) {
	cfg := mock.Config()
	cfg.OpenID.ClientID = "some-client-id"

	openidConfig := mock.NewTestConfiguration(cfg)
	openidConfig.TestProvider.SetIssuer("some-issuer")
	c := newTestClientWithConfig(t, openidConfig)

	expiry := client.DefaultClientAssertionLifetime
	jwtAssertion, err := c.ClientAuthenticationAssertion(expiry)
	require.NoError(t, err)

	assertFlattenedAudience(t, jwtAssertion)

	key := openidConfig.Client().ClientJWK()
	publicKey, err := key.PublicKey()
	require.NoError(t, err)

	alg := openidConfig.Client().ClientJWKAlgorithm()

	opts := []jwt.ParseOption{
		jwt.WithKey(alg, publicKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.NotBeforeKey),
		jwt.WithRequiredClaim(jwt.JwtIDKey),
	}
	assertion, err := jwt.ParseString(jwtAssertion, opts...)
	require.NoError(t, err)

	aud, ok := assertion.Audience()
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"some-issuer"}, aud)

	iss, ok := assertion.Issuer()
	assert.True(t, ok)
	assert.Equal(t, "some-client-id", iss)

	sub, ok := assertion.Subject()
	assert.True(t, ok)
	assert.Equal(t, "some-client-id", sub)

	iat, ok := assertion.IssuedAt()
	assert.True(t, ok)
	assert.True(t, iat.Before(time.Now()))

	nbf, ok := assertion.NotBefore()
	assert.True(t, ok)
	assert.True(t, nbf.Before(time.Now()))
	assert.Equal(t, iat, nbf)

	exp, ok := assertion.Expiration()
	assert.True(t, ok)
	assert.True(t, exp.After(time.Now()))
	assert.True(t, exp.Before(time.Now().Add(expiry)))

	msg, err := jws.ParseString(jwtAssertion)
	assert.NoError(t, err)
	assert.Len(t, msg.Signatures(), 1)
	headers := msg.Signatures()[0].ProtectedHeaders()

	typ, ok := headers.Type()
	assert.True(t, ok)
	assert.Equal(t, "JWT", typ)

	alg, ok = headers.Algorithm()
	assert.True(t, ok)
	assert.Equal(t, jwa.RS256(), alg)

	expectedKid, ok := key.KeyID()
	assert.True(t, ok)
	kid, ok := headers.KeyID()
	assert.True(t, ok)
	assert.Equal(t, expectedKid, kid)
}

func TestClientAuthenticationAssertionHeader(t *testing.T) {
	cfg := mock.Config()
	cfg.OpenID.ClientID = "some-client-id"
	cfg.OpenID.NewClientAuthJWTType = true

	openidConfig := mock.NewTestConfiguration(cfg)
	openidConfig.TestProvider.SetIssuer("some-issuer")
	c := newTestClientWithConfig(t, openidConfig)

	expiry := client.DefaultClientAssertionLifetime
	jwtAssertion, err := c.ClientAuthenticationAssertion(expiry)
	assert.NoError(t, err)

	msg, err := jws.ParseString(jwtAssertion)
	assert.NoError(t, err)
	assert.Len(t, msg.Signatures(), 1)
	headers := msg.Signatures()[0].ProtectedHeaders()

	typ, ok := headers.Type()
	assert.True(t, ok)
	assert.Equal(t, "client-authentication+jwt", typ)
}

func TestClientAuthenticationAssertionAlgorithms(t *testing.T) {
	for _, alg := range []jwa.SignatureAlgorithm{
		jwa.PS256(),
		jwa.PS384(),
		jwa.PS512(),
		jwa.RS384(),
		jwa.RS512(),
		jwa.ES256(),
		jwa.ES384(),
		jwa.ES512(),
		jwa.EdDSAEd25519(),
		// deprecated by RFC 9864, but still accepted for existing client JWKs
		jwa.EdDSA(),
	} {
		t.Run(alg.String(), func(t *testing.T) {
			cfg := mock.Config()
			key, err := crypto.NewJwkWithAlg(alg)
			require.NoError(t, err)

			openidConfig := mock.NewTestConfigurationWithClientJWK(cfg, key)
			openidConfig.TestProvider.SetIssuer("some-issuer")
			c := newTestClientWithConfig(t, openidConfig)

			jwtAssertion, err := c.ClientAuthenticationAssertion(client.DefaultClientAssertionLifetime)
			require.NoError(t, err)

			publicKey, err := key.PublicKey()
			require.NoError(t, err)
			_, err = jwt.ParseString(jwtAssertion, jwt.WithKey(alg, publicKey))
			require.NoError(t, err)

			msg, err := jws.ParseString(jwtAssertion)
			require.NoError(t, err)
			headerAlg, ok := msg.Signatures()[0].ProtectedHeaders().Algorithm()
			require.True(t, ok)
			assert.Equal(t, alg, headerAlg)
		})
	}
}

// The token and pushed authorization endpoints receive client credentials, so a redirect
// must not be followed; doing so would forward the credentials to another host.
func TestClient_RefusesRedirect(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	openidConfig := mock.NewTestConfiguration(mock.Config())
	openidConfig.TestProvider.SetTokenEndpoint(redirector.URL)

	_, err := newTestClientWithConfig(t, openidConfig).
		RefreshGrant(t.Context(), "some-refresh-token", "", "")

	require.Error(t, err)
	assert.ErrorContains(t, err, "refusing to follow redirect")
	assert.False(t, redirected, "the redirect target must not be reached")
}

func TestClient_DPoPNonceRetryMintsFreshAssertionAndProof(t *testing.T) {
	for _, test := range []struct {
		name     string
		runGrant func(*client.Client) error
	}{
		{
			name: "refresh grant",
			runGrant: func(c *client.Client) error {
				response, err := c.RefreshGrant(t.Context(), "refresh-token", "", "")
				if err == nil {
					assert.Equal(t, "DPoP", response.TokenType)
				}

				return err
			},
		},
		{
			name: "auth code grant",
			runGrant: func(c *client.Client) error {
				_, err := c.AuthCodeGrant(t.Context(), "code", "verifier", "https://client.example/callback")
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			const nonce = "server-nonce"
			var assertions []string
			var proofs []string

			tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if !assert.NoError(t, r.ParseForm()) {
					http.Error(w, "invalid test request", http.StatusBadRequest)
					return
				}

				assertions = append(assertions, r.PostForm.Get("client_assertion"))
				proofs = append(proofs, r.Header.Get("DPoP"))

				if len(assertions) == 1 {
					w.Header().Set("DPoP-Nonce", nonce)
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
					return
				}

				_, _ = w.Write([]byte(`{"access_token":"access-token","token_type":"DPoP","refresh_token":"next-refresh-token","expires_in":60}`))
			}))
			defer tokenEndpoint.Close()

			openidConfig := mock.NewTestConfiguration(mock.Config())
			openidConfig.TestClient.OpenID.DPoP = true
			openidConfig.TestProvider.SetTokenEndpoint(tokenEndpoint.URL)

			require.NoError(t, test.runGrant(newTestClientWithConfig(t, openidConfig)))

			require.Len(t, assertions, 2)
			require.Len(t, proofs, 2)
			for _, tokens := range []struct {
				name    string
				encoded []string
			}{
				{name: "client assertions", encoded: assertions},
				{name: "DPoP proofs", encoded: proofs},
			} {
				t.Run(tokens.name, func(t *testing.T) {
					first, err := jwt.ParseInsecure([]byte(tokens.encoded[0]))
					require.NoError(t, err)
					second, err := jwt.ParseInsecure([]byte(tokens.encoded[1]))
					require.NoError(t, err)

					firstID, ok := first.JwtID()
					require.True(t, ok)
					secondID, ok := second.JwtID()
					require.True(t, ok)
					assert.NotEmpty(t, firstID)
					assert.NotEmpty(t, secondID)
					assert.NotEqual(t, firstID, secondID)
				})
			}

			retryProof, err := jwt.ParseInsecure([]byte(proofs[1]))
			require.NoError(t, err)

			var retryNonce string
			require.NoError(t, retryProof.Get("nonce", &retryNonce))

			assert.Equal(t, nonce, retryNonce)
			assert.False(t, retryProof.Has("ath"))
		})
	}
}

func TestClient_DPoPNonceRetryLimit(t *testing.T) {
	grants := []struct {
		name string
		run  func(*client.Client) error
	}{
		{
			name: "refresh grant",
			run: func(c *client.Client) error {
				_, err := c.RefreshGrant(t.Context(), "refresh-token", "", "")
				return err
			},
		},
		{
			name: "auth code grant",
			run: func(c *client.Client) error {
				_, err := c.AuthCodeGrant(t.Context(), "code", "verifier", "https://client.example/callback")
				return err
			},
		},
	}
	errors := []struct {
		name         string
		errorCode    string
		wantRequests int
	}{
		{name: "retries one nonce challenge", errorCode: "use_dpop_nonce", wantRequests: 2},
		{name: "does not retry another DPoP error", errorCode: "invalid_dpop_proof", wantRequests: 1},
	}

	for _, grant := range grants {
		t.Run(grant.name, func(t *testing.T) {
			for _, test := range errors {
				t.Run(test.name, func(t *testing.T) {
					requests := 0
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests++
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("DPoP-Nonce", "nonce")
						w.WriteHeader(http.StatusBadRequest)
						assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": test.errorCode}))
					}))
					defer server.Close()

					cfg := mock.NewTestConfiguration(mock.Config())
					cfg.TestClient.OpenID.DPoP = true
					cfg.TestProvider.SetTokenEndpoint(server.URL)

					err := grant.run(newTestClientWithConfig(t, cfg))
					require.Error(t, err)
					assert.Equal(t, test.wantRequests, requests)
				})
			}
		})
	}
}

// assertFlattenedAudience asserts that the raw JWT assertion has a flattened audience claim, i.e. aud is a string value.
// We do this as the jwx library only exposes the audience as a slice of strings for parsed JWTs.
func assertFlattenedAudience(t *testing.T, jwtAssertion string) {
	parts := strings.Split(jwtAssertion, ".")
	assert.Len(t, parts, 3)

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	assert.NoError(t, err)

	claims := make(map[string]any)
	err = json.Unmarshal(rawClaims, &claims)
	assert.NoError(t, err)

	assert.Equal(t, "some-issuer", claims["aud"])
}

func newTestClientWithConfig(t *testing.T, config *mock.TestConfiguration) *client.Client {
	t.Helper()

	jwksProvider := mock.NewTestJwksProvider()

	c, err := client.NewClient(config, jwksProvider)
	require.NoError(t, err)

	return c
}
