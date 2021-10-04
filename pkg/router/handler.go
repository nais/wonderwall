package router

import (
	"sync"

	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/session"
)

const (
	RedirectURLParameter           = "redirect"
	SecurityLevelURLParameter      = "level"
	LocaleURLParameter             = "locale"
	PostLogoutRedirectURIParameter = "post_logout_redirect_uri"
)

type Handler struct {
	Config        config.IDPorten
	Crypter       cryptutil.Crypter
	OauthConfig   oauth2.Config
	SecureCookies bool
	Sessions      session.Store
	UpstreamHost  string
	jwkSet        jwk.Set
	lock          sync.Mutex
}

func NewHandler(cfg config.IDPorten, crypter cryptutil.Crypter, jwkSet jwk.Set, sessionStore session.Store, upstreamHost string) (*Handler, error) {
	oauthConfig := oauth2.Config{
		ClientID: cfg.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.WellKnown.AuthorizationEndpoint,
			TokenURL: cfg.WellKnown.TokenEndpoint,
		},
		RedirectURL: cfg.RedirectURI,
		Scopes:      cfg.Scopes,
	}

	return &Handler{
		Config:        cfg,
		Crypter:       crypter,
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
