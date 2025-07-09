package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/handler"
	"github.com/nais/wonderwall/pkg/metrics"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/provider"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/server"
	log "github.com/sirupsen/logrus"
	"go.uber.org/automaxprocs/maxprocs"
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

	if _, err := maxprocs.Set(); err != nil {
		log.Debugf("setting GOMAXPROCS: %+v", err)
	}
	if _, err := memlimit.SetGoMemLimitWithOpts(); err != nil {
		log.Debugf("setting GOMEMLIMIT: %+v", err)
	}

	key, err := crypto.EncryptionKeyOrGenerate(cfg)
	if err != nil {
		return err
	}

	crypt := crypto.NewCrypter(key)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.Cookie.Prefix != cookie.DefaultPrefix {
		cookie.ConfigureCookieNamesWithPrefix(cfg.Cookie.Prefix)
	}

	if cfg.SSO.Enabled {
		cookie.ConfigureCookieNamesWithPrefix(cfg.SSO.SessionCookieName)
		cookie.Session = cfg.SSO.SessionCookieName
	}

	if cfg.OpenTelemetry.Enabled {
		otelShutdown, err := otel.Setup(ctx, cfg)
		if err != nil {
			return fmt.Errorf("initializing OpenTelemetry: %w", err)
		}
		defer otelShutdown(ctx)
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

	if cfg.MetricsBindAddress != "" {
		go func() {
			log.Debugf("metrics: listening on %s", cfg.MetricsBindAddress)
			err := metrics.Handle(cfg.MetricsBindAddress, cfg.OpenID.Provider)
			if err != nil {
				log.Fatalf("fatal: metrics server error: %s", err)
			}
		}()
	}

	if cfg.ProbeBindAddress != "" {
		go func() {
			mux := http.NewServeMux()
			healthz := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			})
			mux.HandleFunc("/", healthz)
			mux.HandleFunc("/healthz", healthz)
			log.Debugf("probe: listening on %s", cfg.ProbeBindAddress)
			err := http.ListenAndServe(cfg.ProbeBindAddress, mux)
			if err != nil {
				log.Fatalf("fatal: probe server error: %s", err)
			}
		}()
	}

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
