package session_test

import (
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/session"
)

func testRedisLock(t *testing.T, client *redis.Client) {
	ctx := t.Context()
	lock := session.NewRedisLock(client, "some-key")

	err := lock.Acquire(ctx, time.Minute)
	assert.NoError(t, err)

	err = lock.Acquire(ctx, time.Minute)
	assert.Error(t, err)
	assert.ErrorIs(t, err, session.ErrAcquireLock)

	err = lock.Release(ctx)
	assert.NoError(t, err)
}
