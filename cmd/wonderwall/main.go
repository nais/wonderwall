package main

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	_ "go.uber.org/automaxprocs"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler"
	"github.com/nais/wonderwall/pkg/metrics"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/provider"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/server"
)

func run() error {
	cfg, err := config.Initialize()
	if err != nil {
		return err
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

	cookieOpts := cookie.DefaultOptions()

	jwksProvider, err := provider.NewJwksProvider(ctx, openidConfig)
	if err != nil {
		return err
	}

	h, err := handler.NewHandler(cfg, cookieOpts, jwksProvider, openidConfig, crypt)
	if err != nil {
		return fmt.Errorf("initializing routing handler: %w", err)
	}

	r := router.New(h)

	go func() {
		err := metrics.Handle(cfg.MetricsBindAddress, cfg.OpenID.Provider)
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
