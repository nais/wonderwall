package router

import (
	"github.com/go-chi/chi/v5"
	chi_middleware "github.com/go-chi/chi/v5/middleware"

	"github.com/nais/wonderwall/pkg/config"
	middleware2 "github.com/nais/wonderwall/pkg/router/middleware"
	"github.com/nais/wonderwall/pkg/router/paths"
)

func New(handler *Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware2.CorrelationIDHandler)
	r.Use(chi_middleware.Recoverer)
	prometheusMiddleware := middleware2.NewPrometheusMiddleware("wonderwall")

	prefix := config.ParseIngress(handler.Config.Ingress)

	r.Route(prefix+paths.OAuth2, func(r chi.Router) {
		r.Use(middleware2.LogEntryHandler(handler.Httplogger))
		r.Use(prometheusMiddleware.Handler)
		r.Use(chi_middleware.NoCache)
		r.Get(paths.Login, handler.Login)
		r.Get(paths.Callback, handler.Callback)
		r.Get(paths.Logout, handler.Logout)
		r.Get(paths.FrontChannelLogout, handler.FrontChannelLogout)
	})
	r.HandleFunc("/*", handler.Default)
	return r
}
