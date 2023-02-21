package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/nais/wonderwall/pkg/metrics"
)

type redisSessionStore struct {
	client redis.Cmdable
}

var _ Store = &redisSessionStore{}

func NewRedis(client redis.Cmdable) Store {
	return &redisSessionStore{
		client: client,
	}
}

func (s *redisSessionStore) Read(ctx context.Context, key string) (*EncryptedData, error) {
	encryptedData := &EncryptedData{}
	err := metrics.ObserveRedisLatency(metrics.RedisOperationRead, func() error {
		return s.client.Get(ctx, key).Scan(encryptedData)
	})
	if err == nil {
		return encryptedData, nil
	}

	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
	}

	return nil, err
}

func (s *redisSessionStore) Write(ctx context.Context, key string, value *EncryptedData, expiration time.Duration) error {
	err := metrics.ObserveRedisLatency(metrics.RedisOperationWrite, func() error {
		return s.client.Set(ctx, key, value, expiration).Err()
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *redisSessionStore) Delete(ctx context.Context, keys ...string) error {
	err := metrics.ObserveRedisLatency(metrics.RedisOperationDelete, func() error {
		return s.client.Del(ctx, keys...).Err()
	})
	if err == nil {
		return nil
	}

	if errors.Is(err, redis.Nil) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}

	return err
}

func (s *redisSessionStore) Update(ctx context.Context, key string, value *EncryptedData) error {
	_, err := s.Read(ctx, key)
	if err != nil {
		return err
	}

	err = metrics.ObserveRedisLatency(metrics.RedisOperationUpdate, func() error {
		return s.client.Set(ctx, key, value, redis.KeepTTL).Err()
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *redisSessionStore) MakeLock(key string) Lock {
	return NewRedisLock(s.client, key)
}
