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
	c := client.NewClient(openidConfig)

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

func newTestClientWithConfig(config *mock.TestConfiguration) client.Client {
	return client.NewClient(config)
}

func newTestClient() client.Client {
	return newTestClientWithConfig(mock.NewTestConfiguration(mock.Config()))
}
