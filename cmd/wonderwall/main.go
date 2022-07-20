package main

import (
	"context"
	"fmt"

	"github.com/nais/liberator/pkg/conftools"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler"
	"github.com/nais/wonderwall/pkg/logging"
	"github.com/nais/wonderwall/pkg/metrics"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/server"
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
	if err := cfg.Validate(); err != nil {
		return err
	}

	if err := logging.Setup(cfg.LogLevel, cfg.LogFormat); err != nil {
		return err
	}

	log.Tracef("Trace logging enabled")

	for _, line := range conftools.Format(maskedConfig) {
		log.WithField("logger", "wonderwall.config").Info(line)
	}

	key, err := crypto.EncryptionKeyOrGenerate(cfg)
	if err != nil {
		return err
	}

	openidConfig, err := openidconfig.NewConfig(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crypt := crypto.NewCrypter(key)
	sessionStore := session.NewStore(cfg)
	h, err := handler.NewHandler(ctx, cfg, openidConfig, crypt, sessionStore)
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
	return server.Start(cfg, r)
}

func main() {
	err := run()
	if err != nil {
		log.Fatalf("Fatal error: %s", err)
	}
}
