package router

import (
	"context"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/provider"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	Cfg           openidconfig.Config
	Client        client.Client
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Loginstatus   loginstatus.Client
	Provider      provider.Provider
	Sessions      session.Store
	Httplogger    zerolog.Logger
}

func NewHandler(
	jwksRefreshCtx context.Context,
	cfg openidconfig.Config,
	crypter crypto.Crypter,
	httplogger zerolog.Logger,
	sessionStore session.Store,
) (*Handler, error) {
	loginstatusClient := loginstatus.NewClient(cfg.Wonderwall().Loginstatus, http.DefaultClient)

	cookiePath := config.ParseIngress(cfg.Wonderwall().Ingress)
	cookieOpts := cookie.DefaultOptions().WithPath(cookiePath)

	openidProvider, err := provider.NewProvider(jwksRefreshCtx, cfg)
	if err != nil {
		return nil, err
	}

	openidClient := client.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &Handler{
		Client:        openidClient,
		CookieOptions: cookieOpts,
		Crypter:       crypter,
		Httplogger:    httplogger,
		Loginstatus:   loginstatusClient,
		Cfg:           cfg,
		Provider:      openidProvider,
		Sessions:      sessionStore,
	}, nil
}
