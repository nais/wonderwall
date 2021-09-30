package session

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/metrics"
	"time"
)

type redisSessionStore struct {
	client  redis.Cmdable
	crypter cryptutil.Crypter
}

var _ Store = &redisSessionStore{}

func NewRedis(client redis.Cmdable, crypter cryptutil.Crypter) Store {
	return &redisSessionStore{
		client:  client,
		crypter: crypter,
	}
}

func (s *redisSessionStore) Read(ctx context.Context, key string) (*Data, error) {
	encryptedData := &EncryptedData{}
	err := metrics.ObserveRedisLatency("Read", func() error {
		var err error
		status := s.client.Get(ctx, key)
		err = status.Scan(encryptedData)
		return err
	})
	if err != nil {
		return nil, err
	}

	data, err := encryptedData.Decrypt(s.crypter)
	if err != nil {
		return nil, fmt.Errorf("decrypting session data: %w", err)
	}

	return data, nil
}

func (s *redisSessionStore) Write(ctx context.Context, key string, value *Data, expiration time.Duration) error {
	encryptedData, err := value.Encrypt(s.crypter)
	if err != nil {
		return err
	}

	return metrics.ObserveRedisLatency("Write", func() error {
		status := s.client.Set(ctx, key, encryptedData, expiration)
		return status.Err()
	})
}

func (s *redisSessionStore) Delete(ctx context.Context, keys ...string) error {
	return metrics.ObserveRedisLatency("Delete", func() error {
		status := s.client.Del(ctx, keys...)
		return status.Err()
	})
}
