package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	"github.com/nais/wonderwall/pkg/handler/reverseproxy"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/provider"
	"github.com/nais/wonderwall/pkg/session"
)

func NewHandler(
	ctx context.Context,
	cfg *config.Config,
	cookieOpts cookie.Options,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
) (*StandardHandler, error) {
	openidProvider, err := provider.NewProvider(ctx, openidConfig)
	if err != nil {
		return nil, err
	}

	autoLogin, err := autologin.New(cfg)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	openidClient := client.NewClient(openidConfig)
	openidClient.SetHttpClient(httpClient)

	sessionHandler, err := session.NewHandler(cfg, openidConfig, crypter, openidClient)
	if err != nil {
		return nil, err
	}

	ingresses, err := ingress.ParseIngresses(cfg)
	if err != nil {
		return nil, err
	}

	return &StandardHandler{
		autoLogin:     autoLogin,
		client:        openidClient,
		config:        cfg,
		cookieOptions: cookieOpts,
		crypter:       crypter,
		ingresses:     ingresses,
		loginstatus:   loginstatus.NewClient(cfg.Loginstatus, httpClient),
		openidConfig:  openidConfig,
		provider:      openidProvider,
		sessions:      sessionHandler,
		upstreamProxy: reverseproxy.New(cfg.UpstreamHost),
	}, nil
}
