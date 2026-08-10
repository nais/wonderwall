package client_test

import (
	"encoding/base64"
	"encoding/json"
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
	c := newTestClientWithConfig(openidConfig)

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
	c := newTestClientWithConfig(openidConfig)

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
			c := newTestClientWithConfig(openidConfig)

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

func newTestClientWithConfig(config *mock.TestConfiguration) *client.Client {
	jwksProvider := mock.NewTestJwksProvider()
	return client.NewClient(config, jwksProvider)
}
