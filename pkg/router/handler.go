package router

import (
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	Config       config.Config
	Cookies      cookie.Options
	Crypter      crypto.Crypter
	OauthConfig  oauth2.Config
	Provider     openid.Provider
	Sessions     session.Store
	Httplogger   zerolog.Logger
	lock         sync.Mutex
	tokenRestore TokenRestore
}

type TokenRestore struct {
	ActiveSession bool
	lock          sync.Mutex
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
		RedirectURL: provider.GetClientConfiguration().GetRedirectURI(),
		Scopes:      provider.GetClientConfiguration().GetScopes(),
	}

	return &Handler{
		Config:      cfg,
		Cookies:     cookie.DefaultOptions(),
		Crypter:     crypter,
		Httplogger:  httplogger,
		lock:        sync.Mutex{},
		OauthConfig: oauthConfig,
		Provider:    provider,
		Sessions:    sessionStore,
		tokenRestore: TokenRestore{
			ActiveSession: true,
			lock:          sync.Mutex{},
		},
	}, nil
}
