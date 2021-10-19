package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-redis/redis/v8"
	"github.com/nais/liberator/pkg/conftools"
	"github.com/nais/liberator/pkg/keygen"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/logging"
	"github.com/nais/wonderwall/pkg/metrics"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

var maskedConfig = []string{
	config.OpenIDClientJWK,
	config.EncryptionKey,
	config.RedisPassword,
}

func run() error {
	cfg, err := config.Initialize()
	if err != nil {
		return err
	}
	if err := conftools.Load(cfg); err != nil {
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

	prv, err := openid.NewProvider(cfg)
	if err != nil {
		return err
	}

	crypt := crypto.NewCrypter(key)
	sessionStore := setupSessionStore(cfg)
	httplogger := logging.NewHttpLogger(cfg)
	h, err := router.NewHandler(*cfg, crypt, httplogger, prv, sessionStore)
	if err != nil {
		return fmt.Errorf("initializing routing handler: %w", err)
	}

	r := router.New(h)

	go func() {
		err := metrics.Handle(cfg.MetricsBindAddress)
		if err != nil {
			log.Fatalf("fatal: metrics server error: %s", err)
		}
	}()
	return startServer(cfg, r)
}

func setupSessionStore(cfg *config.Config) session.Store {
	if len(cfg.Redis.Address) == 0 {
		log.Warnf("Redis not configured, using in-memory session backing store; not suitable for multi-pod deployments!")
		return session.NewMemory()
	}

	redisClient, err := configureRedisClient(cfg)
	if err != nil {
		log.Fatalf("Failed to configure Redis: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	err = redisClient.Ping(ctx).Err()
	if err != nil {
		log.Warnf("Failed to connect to configured Redis, using cookie fallback: %v", err)
	}

	log.Infof("Using Redis as session backing store")
	return session.NewRedis(redisClient)
}

func configureRedisClient(cfg *config.Config) (*redis.Client, error) {
	opts := &redis.Options{
		Network:  "tcp",
		Addr:     cfg.Redis.Address,
		Username: cfg.Redis.Username,
		Password: cfg.Redis.Password,
	}

	if cfg.Redis.TLS {
		opts.TLSConfig = &tls.Config{}
	}

	redisClient := redis.NewClient(opts)
	return redisClient, nil
}

func startServer(cfg *config.Config, r chi.Router) error {
	server := http.Server{
		Addr:    cfg.BindAddress,
		Handler: r,
	}

	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		shutdownCtx, shutdownStopCtx := context.WithTimeout(serverCtx, 20*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("graceful shutdown timed out.. forcing exit.")
			}
		}()

		err := server.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		shutdownStopCtx()
		serverStopCtx()
	}()

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	<-serverCtx.Done()
	return nil
}

func main() {
	err := run()
	if err != nil {
		log.Fatalf("Fatal error: %s", err)
	}
}
