package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/nais/wonderwall/pkg/otel"

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

	if cfg.CookiePrefix != cookie.DefaultPrefix {
		cookie.ConfigureCookieNamesWithPrefix(cfg.CookiePrefix)
	}

	if cfg.SSO.Enabled {
		cookie.ConfigureCookieNamesWithPrefix(cfg.SSO.SessionCookieName)
		cookie.Session = cfg.SSO.SessionCookieName
	}

	var src router.Source

	if cfg.SSO.Enabled {
		switch cfg.SSO.Mode {
		case config.SSOModeServer:
			src, err = ssoServer(ctx, cfg, crypt)
		case config.SSOModeProxy:
			src, err = ssoProxy(cfg, crypt)
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

	otelShutdown, err := otel.SetupOTelSDK(ctx,
		envOrDefault("OTEL_SERVICE_NAME", "wonderwall"), "")
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, otelShutdown(context.Background()))
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

	return handler.NewStandalone(cfg, jwksProvider, openidConfig, crypt)
}

func ssoServer(ctx context.Context, cfg *config.Config, crypt crypto.Crypter) (*handler.SSOServer, error) {
	h, err := standalone(ctx, cfg, crypt)
	if err != nil {
		return nil, err
	}

	return handler.NewSSOServer(cfg, h)
}

func ssoProxy(cfg *config.Config, crypt crypto.Crypter) (*handler.SSOProxy, error) {
	return handler.NewSSOProxy(cfg, crypt)
}

func envOrDefault(name string, defaultValue string) string {
	realValue := os.Getenv(name)
	if realValue != "" {
		return realValue
	}
	return defaultValue
}
