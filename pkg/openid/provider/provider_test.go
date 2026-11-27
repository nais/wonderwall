package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJwksProviderRefreshAfterKeyRotation(t *testing.T) {
	initial, err := crypto.NewJwkSet()
	require.NoError(t, err)
	rotated, err := crypto.NewJwkSet()
	require.NoError(t, err)
	rotatedKey, ok := rotated.Public.Key(0)
	require.True(t, ok)
	rotatedID, ok := rotatedKey.KeyID()
	require.True(t, ok)
	require.NoError(t, rotatedKey.Remove(jwk.AlgorithmKey))

	initialBody, err := json.Marshal(initial.Public)
	require.NoError(t, err)
	rotatedBody, err := json.Marshal(rotated.Public)
	require.NoError(t, err)
	var keyRotated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if keyRotated.Load() {
			_, _ = w.Write(rotatedBody)
			return
		}
		_, _ = w.Write(initialBody)
	}))
	t.Cleanup(server.Close)

	cfg := mock.NewTestConfiguration(mock.Config())
	cfg.TestProvider.SetJwksURI(server.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	provider, err := NewJwksProvider(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, provider.jwksCache.Shutdown(ctx))
	})

	keyRotated.Store(true)
	cached, err := provider.GetPublicJwkSet(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, (*cached).Len())
	_, ok = (*cached).LookupKeyID(rotatedID)
	require.False(t, ok)

	refreshed, err := provider.RefreshPublicJwkSet(ctx)
	require.NoError(t, err)
	key, ok := (*refreshed).LookupKeyID(rotatedID)
	require.True(t, ok)
	alg, ok := key.Algorithm()
	require.True(t, ok)
	assert.Equal(t, jwa.RS256(), alg)
}

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
