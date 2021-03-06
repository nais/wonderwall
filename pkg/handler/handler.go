package handler

import (
	"context"
	"net/http"

	"github.com/nais/wonderwall/pkg/autologin"
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
	AutoLogin     *autologin.Options
	Client        client.Client
	Config        *config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Loginstatus   loginstatus.Loginstatus
	OpenIDConfig  openidconfig.Config
	Provider      provider.Provider
	Sessions      session.Store

	path string
}

func NewHandler(
	ctx context.Context,
	cfg *config.Config,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
	sessionStore session.Store,
) (*Handler, error) {
	openidProvider, err := provider.NewProvider(ctx, openidConfig)
	if err != nil {
		return nil, err
	}

	autoLogin, err := autologin.NewOptions(cfg)
	if err != nil {
		return nil, err
	}

	return &Handler{
		AutoLogin:     autoLogin,
		Client:        client.NewClient(openidConfig),
		Config:        cfg,
		CookieOptions: cookie.DefaultOptions().WithPath(config.ParseIngress(cfg.Ingress)),
		Crypter:       crypter,
		Loginstatus:   loginstatus.NewClient(cfg.Loginstatus, http.DefaultClient),
		OpenIDConfig:  openidConfig,
		Provider:      openidProvider,
		Sessions:      sessionStore,
		path:          config.ParseIngress(cfg.Ingress),
	}, nil
}

func (h *Handler) Path() string {
	return h.path
}
