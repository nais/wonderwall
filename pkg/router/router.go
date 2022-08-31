package router

import (
	"github.com/go-chi/chi/v5"
	chi_middleware "github.com/go-chi/chi/v5/middleware"

	"github.com/nais/wonderwall/pkg/handler"
	"github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/router/paths"
)

func New(handler *handler.Handler) chi.Router {
	providerCfg := handler.OpenIDConfig.Provider()
	clientCfg := handler.OpenIDConfig.Client()

	prometheus := middleware.Prometheus(providerCfg.Name())
	ingress := middleware.Ingress(handler.OpenIDConfig)
	logentry := middleware.LogEntry(providerCfg.Name())

	r := chi.NewRouter()
	r.Use(middleware.CorrelationIDHandler)
	r.Use(chi_middleware.Recoverer)
	r.Use(ingress.Handler)

	prefixes := clientCfg.Ingresses().Paths()

	r.Group(func(r chi.Router) {
		r.Use(logentry.Handler)
		r.Use(prometheus.Handler)
		r.Use(chi_middleware.NoCache)

		for _, prefix := range prefixes {
			r.Route(prefix+paths.OAuth2, func(r chi.Router) {
				r.Get(paths.Login, handler.Login)
				r.Get(paths.Callback, handler.Callback)
				r.Get(paths.Logout, handler.Logout)
				r.Get(paths.FrontChannelLogout, handler.FrontChannelLogout)
				r.Get(paths.LogoutCallback, handler.LogoutCallback)
				r.Get(paths.Session, handler.SessionInfo)

				if handler.Config.Session.Refresh {
					r.Get(paths.SessionRefresh, handler.SessionRefresh)
				}
			})
		}
	})

	r.HandleFunc("/*", handler.Default)
	return r
}
