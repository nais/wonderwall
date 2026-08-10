package provider

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/nais/wonderwall/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureJwkSetWithAlg(t *testing.T) {
	missingAlg, err := crypto.NewJwk()
	require.NoError(t, err)
	require.NoError(t, missingAlg.Remove(jwk.AlgorithmKey))

	validAlg, err := crypto.NewJwkWithAlg(jwa.PS256())
	require.NoError(t, err)

	noneAlg, err := crypto.NewJwk()
	require.NoError(t, err)
	require.NoError(t, noneAlg.Set(jwk.AlgorithmKey, jwa.NoSignature()))

	secondNoneAlg, err := crypto.NewJwk()
	require.NoError(t, err)
	require.NoError(t, secondNoneAlg.Set(jwk.AlgorithmKey, jwa.NoSignature()))

	set := jwk.NewSet()
	for _, key := range []jwk.Key{missingAlg, validAlg, noneAlg, secondNoneAlg} {
		require.NoError(t, set.AddKey(key))
	}

	set, err = ensureJwkSetWithAlg(set, jwa.RS256())
	require.NoError(t, err)
	require.Equal(t, 2, set.Len())

	assert.NotEqual(t, -1, set.Index(missingAlg))
	assert.NotEqual(t, -1, set.Index(validAlg))
	assert.Equal(t, -1, set.Index(noneAlg))
	assert.Equal(t, -1, set.Index(secondNoneAlg))

	key, ok := set.Key(set.Index(missingAlg))
	require.True(t, ok)
	alg, ok := key.Algorithm()
	require.True(t, ok)
	assert.Equal(t, jwa.RS256(), alg)

	key, ok = set.Key(set.Index(validAlg))
	require.True(t, ok)
	alg, ok = key.Algorithm()
	require.True(t, ok)
	assert.Equal(t, jwa.PS256(), alg)
}
