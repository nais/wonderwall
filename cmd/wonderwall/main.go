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

	var src router.Source

	if cfg.SSO.Enabled {
		switch cfg.SSO.Mode {
		case config.SSOModeServer:
			src, err = ssoServer(ctx, cfg, crypt)
		case config.SSOModeProxy:
			src, err = ssoProxy(cfg)
		default:
			return fmt.Errorf("invalid SSO mode: %q", cfg.SSO.Mode)
		}
	} else {
		src, err = standalone(ctx, cfg, crypt)
	}
	if err != nil {
		return fmt.Errorf("initializing routing handler: %w", err)
	}

	r := router.New(src, cfg)

	go func() {
		err := metrics.Handle(cfg.MetricsBindAddress, cfg.OpenID.Provider)
		if err != nil {
			log.Fatalf("fatal: metrics server error: %s", err)
		}
	}()
	return server.Start(cfg, r)
}

func standalone(ctx context.Context, cfg *config.Config, crypt crypto.Crypter) (*handler.Standalone, error) {
	openidConfig, err := openidconfig.NewConfig(cfg)
	if err != nil {
		return nil, err
	}

	jwksProvider, err := provider.NewJwksProvider(ctx, openidConfig)
	if err != nil {
		return nil, err
	}

	cookieOpts := cookie.DefaultOptions()

	return handler.NewStandalone(cfg, cookieOpts, jwksProvider, openidConfig, crypt)
}

func ssoServer(ctx context.Context, cfg *config.Config, crypt crypto.Crypter) (*handler.SSOServer, error) {
	h, err := standalone(ctx, cfg, crypt)
	if err != nil {
		return nil, err
	}

	h.CookieOptions = cookie.DefaultOptions().
		WithPath("/").
		WithDomain(cfg.SSO.Domain)

	return handler.NewSSOServer(h)
}

func ssoProxy(cfg *config.Config) (*handler.SSOProxy, error) {
	return handler.NewSSOProxy(cfg)
}
