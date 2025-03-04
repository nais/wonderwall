package session

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/extra/redisprometheus/v9"
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

	collector := redisprometheus.NewCollector("wonderwall", "", redisClient)
	prometheus.Register(collector)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	err = redisClient.Ping(ctx).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to configured Redis: %w", err)
	}

	if cfg.OpenTelemetry.Enabled {
		if err := redisotel.InstrumentTracing(redisClient, redisotel.WithDBStatement(false)); err != nil {
			return nil, fmt.Errorf("failed to instrument Redis Client: %w", err)
		}
		log.Infof("session: using redis as backing store with OpenTelemetry instrumentation")
	} else {
		log.Infof("session: using redis as backing store")
	}

	return NewRedis(redisClient), nil
}
