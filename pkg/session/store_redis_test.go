package session_test

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/pkg/session"
)

var redisTests = map[string]func(*testing.T, *redis.Client){
	"store lifecycle": func(t *testing.T, client *redis.Client) {
		testStoreLifecycle(t, session.NewRedis(client))
	},
	"lock":                                 testRedisLock,
	"update does not recreate deleted key": testUpdateDoesNotRecreateDeletedSession,
}

func TestRedis(t *testing.T) {
	for name, test := range redisTests {
		t.Run(name, func(t *testing.T) {
			test(t, newRedisClient(t, miniredis.RunT(t).Addr()))
		})
	}
}

func testUpdateDoesNotRecreateDeletedSession(t *testing.T, client *redis.Client) {
	store := session.NewRedis(client)
	ctx := t.Context()
	encryptedData := makeEncryptedData(t)

	require.NoError(t, store.Write(ctx, "key", encryptedData, time.Hour))
	require.NoError(t, store.Update(ctx, "key", encryptedData))
	assertTTL(t, client, "key", time.Hour)

	require.NoError(t, store.Delete(ctx, "key"))
	require.ErrorIs(t, store.Update(ctx, "key", encryptedData), session.ErrNotFound)
	assert.Zero(t, client.Exists(ctx, "key").Val())
}

func newRedisClient(t *testing.T, addr string) *redis.Client {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func assertTTL(t *testing.T, client *redis.Client, key string, expected time.Duration, msgAndArgs ...any) {
	t.Helper()
	assert.InDelta(t, expected, client.PTTL(t.Context(), key).Val(), float64(time.Second), msgAndArgs...)
}
