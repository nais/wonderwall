package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/pkg/metrics"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
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
	ctx, span := otel.StartSpan(ctx, "RedisSessionStore.Read")
	defer span.End()
	span.SetAttributes(attribute.Bool("redis.key_exists", false))

	encryptedData := &EncryptedData{}
	err := metrics.ObserveRedisLatency(metrics.RedisOperationRead, func() error {
		return s.client.Get(ctx, key).Scan(encryptedData)
	})
	if err == nil {
		span.SetAttributes(attribute.Bool("redis.key_exists", true))
		return encryptedData, nil
	}

	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
	}

	return nil, err
}

func (s *redisSessionStore) Write(ctx context.Context, key string, value *EncryptedData, expiration time.Duration) error {
	ctx, span := otel.StartSpan(ctx, "RedisSessionStore.Write")
	defer span.End()
	span.SetAttributes(attribute.String("redis.key_expiry", expiration.String()))

	err := metrics.ObserveRedisLatency(metrics.RedisOperationWrite, func() error {
		return s.client.Set(ctx, key, value, expiration).Err()
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *redisSessionStore) Delete(ctx context.Context, keys ...string) error {
	ctx, span := otel.StartSpan(ctx, "RedisSessionStore.Delete")
	defer span.End()

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
	ctx, span := otel.StartSpan(ctx, "RedisSessionStore.Update")
	defer span.End()

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
