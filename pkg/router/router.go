package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chi_middleware "github.com/go-chi/chi/v5/middleware"

	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/router/paths"
)

type Handler interface {
	Login(http.ResponseWriter, *http.Request)
	Callback(http.ResponseWriter, *http.Request)

	Logout(http.ResponseWriter, *http.Request)
	LogoutCallback(http.ResponseWriter, *http.Request)

	FrontChannelLogout(http.ResponseWriter, *http.Request)

	SessionInfo(http.ResponseWriter, *http.Request)
	SessionRefresh(http.ResponseWriter, *http.Request)

	Default(http.ResponseWriter, *http.Request)

	Ingresses() *ingress.Ingresses
	ProviderName() string
}

func New(handler Handler) chi.Router {
	ingressMw := middleware.Ingress(handler)
	prometheus := middleware.Prometheus(handler.ProviderName())
	logentry := middleware.LogEntry(handler.ProviderName())

	r := chi.NewRouter()
	r.Use(middleware.CorrelationIDHandler)
	r.Use(chi_middleware.Recoverer)
	r.Use(ingressMw.Handler)

	prefixes := handler.Ingresses().Paths()

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
				r.Get(paths.SessionRefresh, handler.SessionRefresh)
			})
		}
	})

	r.HandleFunc("/*", handler.Default)
	return r
}
