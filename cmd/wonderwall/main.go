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

func main() {
	err := run()
	if err != nil {
		log.Fatalf("Fatal error: %s", err)
	}
}

func run() error {
	cfg, err := config.Initialize()
	if err != nil {
		return err
	}

	key, err := crypto.EncryptionKeyOrGenerate(cfg)
	if err != nil {
		return err
	}

	crypt := crypto.NewCrypter(key)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var h router.Source

	if cfg.SSO.Enabled {
		switch cfg.SSO.Mode {
		case config.SSOModeServer:
			h, err = ssoServerHandler()
		case config.SSOModeProxy:
			h, err = ssoProxyHandler()
		default:
			return fmt.Errorf("invalid SSO mode: %q", cfg.SSO.Mode)
		}
	} else {
		h, err = standaloneHandler(ctx, cfg, crypt)
	}

	if err != nil {
		return fmt.Errorf("initializing routing handler: %w", err)
	}
	r := router.New(h, cfg)

	go func() {
		err := metrics.Handle(cfg.MetricsBindAddress, cfg.OpenID.Provider)
		if err != nil {
			log.Fatalf("fatal: metrics server error: %s", err)
		}
	}()
	return server.Start(cfg, r)
}

func standaloneHandler(ctx context.Context, cfg *config.Config, crypt crypto.Crypter) (router.Source, error) {
	openidConfig, err := openidconfig.NewConfig(cfg)
	if err != nil {
		return nil, err
	}

	jwksProvider, err := provider.NewJwksProvider(ctx, openidConfig)
	if err != nil {
		return nil, err
	}

	cookieOpts := cookie.DefaultOptions()

	return handler.NewHandler(cfg, cookieOpts, jwksProvider, openidConfig, crypt)
}

func ssoServerHandler() (router.Source, error) {
	//TODO implement me
	panic("implement me")
}

func ssoProxyHandler() (router.Source, error) {
	//TODO implement me
	panic("implement me")
}
