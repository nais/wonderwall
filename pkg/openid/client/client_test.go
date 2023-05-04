package client_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
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
	assertionString, err := c.MakeAssertion(expiry)
	assert.NoError(t, err)

	key := openidConfig.Client().ClientJWK()
	publicKey, err := key.PublicKey()
	assert.NoError(t, err)
	opts := []jwt.ParseOption{
		jwt.WithKey(publicKey.Algorithm(), publicKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.JwtIDKey),
	}

	assertion, err := jwt.Parse([]byte(assertionString), opts...)
	assert.NoError(t, err)

	assert.ElementsMatch(t, []string{"some-issuer"}, assertion.Audience())
	assert.Equal(t, "some-client-id", assertion.Issuer())
	assert.Equal(t, "some-client-id", assertion.Subject())

	assert.True(t, assertion.IssuedAt().Before(time.Now()))
	assert.True(t, assertion.Expiration().After(time.Now()))
	assert.True(t, assertion.Expiration().Before(time.Now().Add(expiry)))
}

func TestStateMismatchError(t *testing.T) {
	for _, tt := range []struct {
		name, expected, actual string
		assertion              assert.ErrorAssertionFunc
	}{
		{"missing actual state", "expected", "", assert.Error},
		{"state mismatch", "match", "not-match", assert.Error},
		{"state match", "match", "match", assert.NoError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := client.StateMismatchError(tt.expected, tt.actual)
			tt.assertion(t, err)
		})
	}
}

func newTestClientWithConfig(config *mock.TestConfiguration) *client.Client {
	jwksProvider := mock.NewTestJwksProvider()
	return client.NewClient(config, jwksProvider)
}

func newTestClient() *client.Client {
	return newTestClientWithConfig(mock.NewTestConfiguration(mock.Config()))
}
