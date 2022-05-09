package router

import (
	"net/http"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	Config        config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	OauthConfig   oauth2.Config
	Loginstatus   loginstatus.Client
	Provider      openid.Provider
	Sessions      session.Store
	lock          sync.Mutex
	Httplogger    zerolog.Logger
}

func NewHandler(
	cfg config.Config,
	crypter crypto.Crypter,
	httplogger zerolog.Logger,
	provider openid.Provider,
	sessionStore session.Store,
) (*Handler, error) {
	oauthConfig := oauth2.Config{
		ClientID: provider.GetClientConfiguration().GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.GetOpenIDConfiguration().AuthorizationEndpoint,
			TokenURL: provider.GetOpenIDConfiguration().TokenEndpoint,
		},
		RedirectURL: provider.GetClientConfiguration().GetCallbackURI(),
		Scopes:      provider.GetClientConfiguration().GetScopes(),
	}
	loginstatusClient := loginstatus.NewClient(cfg.Loginstatus, http.DefaultClient)

	cookiePath := config.ParseIngress(cfg.Ingress)
	cookieOpts := cookie.DefaultOptions().WithPath(cookiePath)

	return &Handler{
		Config:        cfg,
		CookieOptions: cookieOpts,
		Crypter:       crypter,
		Httplogger:    httplogger,
		lock:          sync.Mutex{},
		Loginstatus:   loginstatusClient,
		OauthConfig:   oauthConfig,
		Provider:      provider,
		Sessions:      sessionStore,
	}, nil
}
