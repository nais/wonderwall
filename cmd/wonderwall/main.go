package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/go-redis/redis/v8"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nais/liberator/pkg/conftools"
	"github.com/nais/liberator/pkg/keygen"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/logging"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

var maskedConfig = []string{
	config.IDPortenClientJWK,
	config.EncryptionKey,
}

func run() error {
	cfg := config.Initialize()
	if err := conftools.Load(cfg); err != nil {
		return err
	}

	if err := cfg.FetchWellKnownConfig(); err != nil {
		return err
	}

	if err := logging.Setup(cfg.LogLevel, cfg.LogFormat); err != nil {
		return err
	}

	log.Tracef("Trace logging enabled")

	for _, line := range conftools.Format(maskedConfig) {
		log.Info(line)
	}

	key, err := base64.StdEncoding.DecodeString(cfg.EncryptionKey)
	if err != nil {
		if len(cfg.EncryptionKey) > 0 {
			return fmt.Errorf("decode encryption key: %w", err)
		}
	}

	if len(key) == 0 {
		key, err = keygen.Keygen(32)
		if err != nil {
			return fmt.Errorf("generate random encryption key: %w", err)
		}
	}

	crypt := cryptutil.New(key)

	var sessionStore session.Store
	if len(cfg.Redis) > 0 {
		redisClient := redis.NewClient(&redis.Options{
			Network: "tcp",
			Addr:    cfg.Redis,
		})
		sessionStore = session.NewRedis(redisClient)
		log.Infof("Using Redis as session backing store")
	} else {
		sessionStore = session.NewMemory()
		log.Warnf("Redis not configured, using in-memory session backing store; not suitable for multi-pod deployments!")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jwkSet, err := jwk.Fetch(ctx, cfg.IDPorten.WellKnown.JwksURI)
	if err != nil {
		return fmt.Errorf("fetching jwks: %w", err)
	}

	handler, err := router.NewHandler(cfg.IDPorten, crypt, jwkSet, sessionStore, cfg.UpstreamHost)
	if err != nil {
		return fmt.Errorf("initializing routing handler: %w", err)
	}

	r := router.New(handler)

	return http.ListenAndServe(cfg.BindAddress, r)
}

func main() {
	err := run()
	if err != nil {
		log.Errorf("Fatal error: %s", err)
		os.Exit(1)
	}
}
