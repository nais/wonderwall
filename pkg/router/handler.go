package router

import (
	"github.com/rs/zerolog"
	"sync"

	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	Config        config.Config
	Crypter       cryptutil.Crypter
	OauthConfig   oauth2.Config
	SecureCookies bool
	Sessions      session.Store
	UpstreamHost  string
	jwkSet        jwk.Set
	lock          sync.Mutex
	httplogger    zerolog.Logger
}

func NewHandler(
	cfg config.Config,
	crypter cryptutil.Crypter,
	httplogger zerolog.Logger,
	jwkSet jwk.Set,
	sessionStore session.Store,
	upstreamHost string,
) (*Handler, error) {
	oauthConfig := oauth2.Config{
		ClientID: cfg.IDPorten.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.IDPorten.WellKnown.AuthorizationEndpoint,
			TokenURL: cfg.IDPorten.WellKnown.TokenEndpoint,
		},
		RedirectURL: cfg.IDPorten.RedirectURI,
		Scopes:      cfg.IDPorten.Scopes,
	}

	return &Handler{
		Config:        cfg,
		Crypter:       crypter,
		httplogger:    httplogger,
		jwkSet:        jwkSet,
		lock:          sync.Mutex{},
		OauthConfig:   oauthConfig,
		Sessions:      sessionStore,
		SecureCookies: true,
		UpstreamHost:  upstreamHost,
	}, nil
}

func (h *Handler) WithSecureCookie(enabled bool) *Handler {
	h.SecureCookies = enabled
	return h
}
