package router

import (
	"github.com/go-chi/chi/v5"
	chi_middleware "github.com/go-chi/chi/v5/middleware"

	"github.com/nais/wonderwall/pkg/middleware"
)

func New(handler *Handler, prefixes []string) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.CorrelationIDHandler)
	r.Use(middleware.LogEntryHandler(handler.httplogger))
	r.Use(chi_middleware.Recoverer)
	prometheusMiddleware := middleware.NewPrometheusMiddleware("wonderwall")

	for _, prefix := range prefixes {
		r.Route(prefix+"/oauth2", func(r chi.Router) {
			r.Use(prometheusMiddleware.Handler)
			r.Use(chi_middleware.NoCache)
			r.Get("/login", handler.Login)
			r.Get("/callback", handler.Callback)
			r.Get("/logout", handler.Logout)
			r.Get("/logout/frontchannel", handler.FrontChannelLogout)
		})
	}
	r.HandleFunc("/*", handler.Default)
	return r
}
