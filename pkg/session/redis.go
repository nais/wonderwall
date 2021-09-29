package session

import (
	"context"
	"github.com/go-redis/redis/v8"
	"github.com/nais/wonderwall/pkg/metrics"
	"time"
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

func (s *redisSessionStore) Read(ctx context.Context, key string) (*Data, error) {
	data := &Data{}
	err := metrics.ObserveRedisLatency("Read", func() error {
		var err error
		status := s.client.Get(ctx, key)
		err = status.Scan(data)
		return err
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *redisSessionStore) Write(ctx context.Context, key string, value *Data, expiration time.Duration) error {
	return metrics.ObserveRedisLatency("Write", func() error {
		status := s.client.Set(ctx, key, value, expiration)
		return status.Err()
	})
}

func (s *redisSessionStore) Delete(ctx context.Context, keys ...string) error {
	return metrics.ObserveRedisLatency("Delete", func() error {
		status := s.client.Del(ctx, keys...)
		return status.Err()
	})
}
