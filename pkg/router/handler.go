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
	Client        client.Client
	Config        *config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Loginstatus   loginstatus.Client
	OpenIDConfig  openidconfig.Config
	Provider      provider.Provider
	Sessions      session.Store
	Httplogger    zerolog.Logger
}

func NewHandler(
	cfg *config.Config,
	crypter crypto.Crypter,
	httplogger zerolog.Logger,
	openidConfig openidconfig.Config,
	sessionStore session.Store,
) (*Handler, error) {
	loginstatusClient := loginstatus.NewClient(cfg.Loginstatus, http.DefaultClient)

	cookiePath := config.ParseIngress(cfg.Ingress)
	cookieOpts := cookie.DefaultOptions().WithPath(cookiePath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	openidProvider, err := provider.NewProvider(ctx, openidConfig)
	if err != nil {
		return nil, err
	}

	openidClient := client.NewClient(openidConfig)
	if err != nil {
		return nil, err
	}

	return &Handler{
		Client:        openidClient,
		Config:        cfg,
		CookieOptions: cookieOpts,
		Crypter:       crypter,
		Httplogger:    httplogger,
		Loginstatus:   loginstatusClient,
		OpenIDConfig:  openidConfig,
		Provider:      openidProvider,
		Sessions:      sessionStore,
	}, nil
}
