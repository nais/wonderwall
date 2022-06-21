package router

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	Client        openid.Client
	Config        config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Loginstatus   loginstatus.Client
	Provider      openid.Provider
	Sessions      session.Store
	Httplogger    zerolog.Logger
}

func NewHandler(
	cfg config.Config,
	crypter crypto.Crypter,
	httplogger zerolog.Logger,
	provider openid.Provider,
	sessionStore session.Store,
) (*Handler, error) {
	client := openid.NewClient(cfg, provider)
	loginstatusClient := loginstatus.NewClient(cfg.Loginstatus, http.DefaultClient)

	cookiePath := config.ParseIngress(cfg.Ingress)
	cookieOpts := cookie.DefaultOptions().WithPath(cookiePath)

	return &Handler{
		Client:        client,
		Config:        cfg,
		CookieOptions: cookieOpts,
		Crypter:       crypter,
		Httplogger:    httplogger,
		Loginstatus:   loginstatusClient,
		Provider:      provider,
		Sessions:      sessionStore,
	}, nil
}
