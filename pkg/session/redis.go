package session

import (
	"context"
	"github.com/go-redis/redis/v8"
	"time"
)

type redisSessionStore struct {
	client redis.Cmdable
}

var _ Session = &redisSessionStore{}

func NewRedis(client redis.Cmdable) Session {
	return &redisSessionStore{
		client: client,
	}
}

func (s *redisSessionStore) Read(ctx context.Context, key string) (*Data, error) {
	data := &Data{}
	status := s.client.Get(ctx, key)
	err := status.Scan(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *redisSessionStore) Write(ctx context.Context, key string, value *Data, expiration time.Duration) error {
	status := s.client.Set(ctx, key, value, expiration)
	return status.Err()
}

func (s *redisSessionStore) Delete(ctx context.Context, keys ...string) error {
	status := s.client.Del(ctx, keys...)
	return status.Err()
}
