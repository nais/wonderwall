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
		name          string
		nonce         string
		tokenResponse string
		runGrant      func(*client.Client) error
	}{
		{
			name:          "refresh grant",
			nonce:         "server-nonce",
			tokenResponse: `{"access_token":"access-token","token_type":"DPoP","refresh_token":"next-refresh-token","expires_in":60}`,
			runGrant: func(c *client.Client) error {
				response, err := c.RefreshGrant(t.Context(), "refresh-token", "", "")
				if err == nil {
					assert.Equal(t, "DPoP", response.TokenType)
				}

				return err
			},
		},
		{
			name:          "auth code grant",
			nonce:         "auth-code-nonce",
			tokenResponse: `{"access_token":"access-token","id_token":"id-token","token_type":"DPoP","expires_in":60}`,
			runGrant: func(c *client.Client) error {
				_, err := c.AuthCodeGrant(t.Context(), "code", "verifier", "https://client.example/callback")
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runDPoPNonceRetry(t, test.tokenResponse, test.nonce, test.runGrant)
		})
	}
}

func TestClient_AuthCodeGrantValidatesTokenResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"id-token","expires_in":60}`))
	}))
	defer server.Close()

	openidConfig := mock.NewTestConfiguration(mock.Config())
	openidConfig.TestProvider.SetTokenEndpoint(server.URL)

	_, err := newTestClientWithConfig(t, openidConfig).
		AuthCodeGrant(t.Context(), "code", "verifier", "https://client.example/callback")
	require.ErrorContains(t, err, "missing access_token")
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

func TestNewClient_DPoPProviderCapability(t *testing.T) {
	for _, test := range []struct {
		name               string
		supported          []string
		useClientAlgorithm bool
		wantActive         bool
	}{
		{name: "matching", useClientAlgorithm: true, wantActive: true},
		{name: "unsupported", supported: []string{"PS256"}},
		{name: "absent"},
	} {
		t.Run(test.name, func(t *testing.T) {
			openidConfig := mock.NewTestConfiguration(mock.Config())
			openidConfig.TestProvider.SetTokenEndpoint("https://provider.example/token")
			if test.useClientAlgorithm {
				test.supported = []string{openidConfig.Client().ClientJWKAlgorithm().String()}
			}
			openidConfig.TestProvider.Metadata.DPoPSigningAlgValuesSupported = test.supported

			c, err := client.NewClient(openidConfig, nil)
			require.NoError(t, err)

			if test.wantActive {
				assert.NotEmpty(t, c.DPoPThumbprint())
			} else {
				assert.Empty(t, c.DPoPThumbprint())
			}
		})
	}
}

func newTestClientWithConfig(t *testing.T, config *mock.TestConfiguration) *client.Client {
	t.Helper()

	jwksProvider := mock.NewTestJwksProvider()

	c, err := client.NewClient(config, jwksProvider)
	require.NoError(t, err)

	return c
}

func runDPoPNonceRetry(t *testing.T, response, expectedNonce string, grant func(*client.Client) error) {
	t.Helper()

	var assertions []string
	var proofs []string

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, r.ParseForm())

		assertions = append(assertions, r.PostForm.Get("client_assertion"))
		proofs = append(proofs, r.Header.Get("DPoP"))

		if len(assertions) == 1 {
			w.Header().Set("DPoP-Nonce", expectedNonce)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		_, _ = w.Write([]byte(response))
	}))
	defer tokenEndpoint.Close()

	openidConfig := mock.NewTestConfiguration(mock.Config())
	openidConfig.TestProvider.SetTokenEndpoint(tokenEndpoint.URL)
	openidConfig.TestProvider.Metadata.DPoPSigningAlgValuesSupported = []string{openidConfig.Client().ClientJWKAlgorithm().String()}

	require.NoError(t, grant(newTestClientWithConfig(t, openidConfig)))

	require.Len(t, assertions, 2)
	assert.NotEqual(t, assertions[0], assertions[1])
	require.Len(t, proofs, 2)
	assert.NotEqual(t, proofs[0], proofs[1])

	retryProof, err := jwt.ParseInsecure([]byte(proofs[1]))
	require.NoError(t, err)

	var retryNonce string
	require.NoError(t, retryProof.Get("nonce", &retryNonce))
	assert.Equal(t, expectedNonce, retryNonce)
	assert.False(t, retryProof.Has("ath"))
}
