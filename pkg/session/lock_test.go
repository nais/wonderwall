package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/session"
)

func TestRedisLock(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer s.Close()

	client := redis.NewClient(&redis.Options{
		Network: "tcp",
		Addr:    s.Addr(),
	})

	key := "some-key"
	ctx := context.Background()
	lock := session.NewRedisLock(client, key)

	err = lock.Acquire(ctx, time.Minute)
	assert.NoError(t, err)

	err = lock.Acquire(ctx, time.Minute)
	assert.Error(t, err)
	assert.ErrorIs(t, err, session.AcquireLockError)

	err = lock.Release(ctx)
	assert.NoError(t, err)
}
