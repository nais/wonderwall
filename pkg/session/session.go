package session

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
)

type Store interface {
	Write(ctx context.Context, key string, value *EncryptedData, expiration time.Duration) error
	Read(ctx context.Context, key string) (*EncryptedData, error)
	Delete(ctx context.Context, keys ...string) error
}

func NewStore(cfg *config.Config) Store {
	if len(cfg.Redis.Address) == 0 {
		log.Warnf("Redis not configured, using in-memory session backing store; not suitable for multi-pod deployments!")
		return NewMemory()
	}

	redisClient, err := cfg.Redis.Client()
	if err != nil {
		log.Fatalf("Failed to configure Redis: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	err = redisClient.Ping(ctx).Err()
	if err != nil {
		log.Warnf("Failed to connect to configured Redis, using cookie fallback: %v", err)
	} else {
		log.Infof("Using Redis as session backing store")
	}

	return NewRedis(redisClient)
}
