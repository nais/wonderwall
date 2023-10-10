package session

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
)

type Store interface {
	Write(ctx context.Context, key string, value *EncryptedData, expiration time.Duration) error
	Read(ctx context.Context, key string) (*EncryptedData, error)
	Delete(ctx context.Context, keys ...string) error
	Update(ctx context.Context, key string, value *EncryptedData) error

	MakeLock(key string) Lock
}

func NewStore(cfg *config.Config) (Store, error) {
	if len(cfg.Redis.Address) == 0 && len(cfg.Redis.URI) == 0 {
		log.Warnf("Redis not configured, using in-memory session backing store; not suitable for multi-pod deployments!")
		return NewMemory(), nil
	}

	redisClient, err := cfg.Redis.Client()
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis Client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	err = redisClient.Ping(ctx).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to configured Redis: %w", err)
	} else {
		log.Infof("Using Redis as session backing store")
	}

	return NewRedis(redisClient), nil
}
