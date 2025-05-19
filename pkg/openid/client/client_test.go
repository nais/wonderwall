package client_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestMakeAssertion(t *testing.T) {
	cfg := mock.Config()
	cfg.OpenID.ClientID = "some-client-id"

	openidConfig := mock.NewTestConfiguration(cfg)
	openidConfig.TestProvider.SetIssuer("some-issuer")
	c := newTestClientWithConfig(openidConfig)

	expiry := 30 * time.Second
	jwtAssertion, err := c.MakeAssertion(expiry)
	assert.NoError(t, err)

	assertFlattenedAudience(t, jwtAssertion)

	key := openidConfig.Client().ClientJWK()
	publicKey, err := key.PublicKey()
	assert.NoError(t, err)

	alg, ok := publicKey.Algorithm()
	assert.True(t, ok)

	opts := []jwt.ParseOption{
		jwt.WithKey(alg, publicKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.JwtIDKey),
	}
	assertion, err := jwt.ParseString(jwtAssertion, opts...)
	assert.NoError(t, err)

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

	exp, ok := assertion.Expiration()
	assert.True(t, ok)
	assert.True(t, exp.After(time.Now()))
	assert.True(t, exp.Before(time.Now().Add(expiry)))
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

func newTestClient() *client.Client {
	return newTestClientWithConfig(mock.NewTestConfiguration(mock.Config()))
}
