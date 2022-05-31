package openid_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

func TestAssertion(t *testing.T) {
	provider := mock.NewTestProvider()
	provider.OpenIDConfiguration.Issuer = "some-issuer"
	provider.ClientConfiguration.ClientID = "client-id"
	provider.ClientConfiguration.Scopes = scopes.DefaultScopes()

	expiry := 30 * time.Second
	assertionString, err := openid.ClientAssertion(provider, expiry)
	assert.NoError(t, err)

	key := provider.GetClientConfiguration().GetClientJWK()
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
	assert.Equal(t, "client-id", assertion.Issuer())
	assert.Equal(t, "client-id", assertion.Subject())

	scps, ok := assertion.Get("scope")
	assert.True(t, ok)
	assert.Equal(t, "openid", scps)

	assert.True(t, assertion.IssuedAt().Before(time.Now()))
	assert.True(t, assertion.Expiration().After(time.Now()))
	assert.True(t, assertion.Expiration().Before(time.Now().Add(expiry)))
}
