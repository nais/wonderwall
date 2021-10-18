package router

import (
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/provider"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	Config        config.Config
	Crypter       cryptutil.Crypter
	OauthConfig   oauth2.Config
	Provider      provider.Provider
	SecureCookies bool
	Sessions      session.Store
	lock          sync.Mutex
	httplogger    zerolog.Logger
}

func NewHandler(
	cfg config.Config,
	crypter cryptutil.Crypter,
	httplogger zerolog.Logger,
	provider provider.Provider,
	sessionStore session.Store,
) (*Handler, error) {
	oauthConfig := oauth2.Config{
		ClientID: provider.GetClientConfiguration().GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.GetOpenIDConfiguration().AuthorizationEndpoint,
			TokenURL: provider.GetOpenIDConfiguration().TokenEndpoint,
		},
		RedirectURL: provider.GetClientConfiguration().GetRedirectURI(),
		Scopes:      provider.GetClientConfiguration().GetScopes(),
	}

	return &Handler{
		Config:        cfg,
		Crypter:       crypter,
		httplogger:    httplogger,
		lock:          sync.Mutex{},
		OauthConfig:   oauthConfig,
		Provider:      provider,
		Sessions:      sessionStore,
		SecureCookies: true,
	}, nil
}

func (h *Handler) WithSecureCookie(enabled bool) *Handler {
	h.SecureCookies = enabled
	return h
}
