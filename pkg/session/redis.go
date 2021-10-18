package session

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"

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
	err := metrics.ObserveRedisLatency("Read", func() error {
		return s.client.Get(ctx, key).Scan(encryptedData)
	})
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

func (s *redisSessionStore) Write(ctx context.Context, key string, value *EncryptedData, expiration time.Duration) error {
	return metrics.ObserveRedisLatency("Write", func() error {
		return s.client.Set(ctx, key, value, expiration).Err()
	})
}

func (s *redisSessionStore) Delete(ctx context.Context, keys ...string) error {
	return metrics.ObserveRedisLatency("Delete", func() error {
		return s.client.Del(ctx, keys...).Err()
	})
}
