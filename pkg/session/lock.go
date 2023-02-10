package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bsm/redislock"
	"github.com/redis/go-redis/v9"
)

const (
	KeyTemplate = "%s.lock"
)

var (
	ErrAcquireLock = errors.New("could not acquire lock")
)

type Lock interface {
	Acquire(ctx context.Context, duration time.Duration) error
	Release(ctx context.Context) error
}

var _ Lock = &RedisLock{}

type RedisLock struct {
	locker *redislock.Client
	lock   *redislock.Lock
	key    string
}

func NewRedisLock(client redis.Cmdable, key string) *RedisLock {
	return &RedisLock{
		locker: redislock.New(client),
		key:    key,
	}
}

func (r *RedisLock) Acquire(ctx context.Context, duration time.Duration) error {
	lock, err := r.locker.Obtain(ctx, lockKey(r.key), duration, nil)
	if errors.Is(err, redislock.ErrNotObtained) {
		return ErrAcquireLock
	}
	if err != nil {
		return err
	}

	r.lock = lock
	return nil
}

func (r *RedisLock) Release(ctx context.Context) error {
	return r.lock.Release(ctx)
}

var _ Lock = &NoOpLock{}

type NoOpLock struct{}

func NewNoOpLock() *NoOpLock {
	return new(NoOpLock)
}

func (n *NoOpLock) Acquire(_ context.Context, _ time.Duration) error {
	return nil
}

func (n *NoOpLock) Release(_ context.Context) error {
	return nil
}

func lockKey(key string) string {
	return fmt.Sprintf(KeyTemplate, key)
}
