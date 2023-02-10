package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chi_middleware "github.com/go-chi/chi/v5/middleware"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/router/paths"
)

type Source interface {
	Handlers
	Config
}

type Handlers interface {
	// Login initiates the authorization code flow.
	Login(http.ResponseWriter, *http.Request)
	// LoginCallback handles the authentication response from the identity provider.
	LoginCallback(http.ResponseWriter, *http.Request)
	// Logout triggers self-initiated logout for the current user, as well as single-logout at the identity provider.
	Logout(http.ResponseWriter, *http.Request)
	// LogoutCallback handles the callback initiated by the self-initiated logout after single-logout at the identity provider.
	LogoutCallback(http.ResponseWriter, *http.Request)
	// LogoutFrontChannel performs a local logout initiated by a third party in the SSO circle-of-trust.
	LogoutFrontChannel(http.ResponseWriter, *http.Request)
	// LogoutLocal clears the current user's local session for logout, without triggering single-logout at the identity provider.
	LogoutLocal(http.ResponseWriter, *http.Request)
	// Session returns metadata for the current user's session.
	Session(http.ResponseWriter, *http.Request)
	// SessionRefresh refreshes current user's session and returns the associated updated metadata.
	SessionRefresh(http.ResponseWriter, *http.Request)
	// ReverseProxy proxies all requests upstream.
	ReverseProxy(http.ResponseWriter, *http.Request)
}

type Config interface {
	GetIngresses() *ingress.Ingresses
}

func New(src Source, cfg *config.Config) chi.Router {
	providerName := string(cfg.OpenID.Provider)
	ingressMw := middleware.Ingress(src)
	prometheus := middleware.Prometheus(providerName)
	logentry := middleware.LogEntry(providerName)

	r := chi.NewRouter()
	r.Use(middleware.CorrelationIDHandler)
	r.Use(chi_middleware.Recoverer)
	r.Use(ingressMw.Handler)

	prefixes := src.GetIngresses().Paths()

	r.Group(func(r chi.Router) {
		r.Use(logentry.Handler)
		r.Use(prometheus.Handler)
		r.Use(chi_middleware.NoCache)

		for _, prefix := range prefixes {
			r.Route(prefix+paths.OAuth2, func(r chi.Router) {
				r.Get(paths.Login, src.Login)
				r.Get(paths.LoginCallback, src.LoginCallback)
				r.Get(paths.Logout, src.Logout)
				r.Get(paths.LogoutCallback, src.LogoutCallback)
				r.Get(paths.LogoutFrontChannel, src.LogoutFrontChannel)
				r.Get(paths.LogoutLocal, src.LogoutLocal)
				r.Get(paths.Session, src.Session)
				r.Get(paths.SessionRefresh, src.SessionRefresh) // TODO: for legacy purposes, remove after grace period
				r.Post(paths.SessionRefresh, src.SessionRefresh)
			})
		}
	})

	r.HandleFunc("/*", src.ReverseProxy)
	return r
}
