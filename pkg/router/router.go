package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chi_middleware "github.com/go-chi/chi/v5/middleware"
	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/riandyrn/otelchi"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/router/paths"
)

var noopHandler = func(w http.ResponseWriter, r *http.Request) {}

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
	// SessionRefresh forces a refresh of the current user's session and returns the associated updated metadata.
	SessionRefresh(http.ResponseWriter, *http.Request)
	// SessionForwardAuth checks the current user's session and refreshes it, if necessary.
	// For use in forward authentication scenarios.
	SessionForwardAuth(w http.ResponseWriter, r *http.Request)
	// Wildcard handles all requests not matching the other handlers.
	Wildcard(http.ResponseWriter, *http.Request)
}

type Config interface {
	GetIngresses() *ingress.Ingresses
}

func New(src Source, cfg *config.Config) chi.Router {
	providerName := string(cfg.OpenID.Provider)
	ingressMw := middleware.Ingress(src)
	prometheus := middleware.Prometheus(providerName)
	logger := middleware.Logger(providerName)

	r := chi.NewRouter()
	r.Use(middleware.CorrelationIDHandler)
	if cfg.OpenTelemetry.Enabled {
		r.Use(otelchi.Middleware(cfg.OpenTelemetry.ServiceName,
			otelchi.WithChiRoutes(r),
			otelchi.WithRequestMethodInSpanName(true),
		))
		r.Use(otel.Middleware)
	}
	r.Use(chi_middleware.Recoverer)
	r.Use(ingressMw.Handler)
	r.Use(logger.Handler)

	prefixes := src.GetIngresses().Paths()

	cors := func(allowedMethods ...string) func(http.Handler) http.Handler {
		return middleware.Cors(cfg, allowedMethods)
	}

	r.Group(func(r chi.Router) {
		r.Use(prometheus.Handler)
		r.Use(chi_middleware.NoCache)

		for _, prefix := range prefixes {
			r.Route(prefix+paths.OAuth2, func(r chi.Router) {
				r.Group(func(r chi.Router) {
					if cfg.Session.ForwardAuth {
						r.Use(cors(http.MethodGet, http.MethodHead))
						r.Use(httpinternal.DisallowNonNavigationalRequests)
						// Cors middleware is designed to be used as a top-level middleware on the chi router.
						// Applying with within a r.Group() or using With() will not work without routes matching OPTIONS added.
						r.Options(paths.Login, noopHandler)
						r.Options(paths.Logout, noopHandler)
					}
					r.Get(paths.Login, src.Login)
					r.Get(paths.Logout, src.Logout)
					r.Head(paths.Login, src.Login)
					r.Head(paths.Logout, src.Logout)
					r.Get(paths.LoginCallback, src.LoginCallback)
					r.Get(paths.LogoutCallback, src.LogoutCallback)
				})

				r.Get(paths.LogoutFrontChannel, src.LogoutFrontChannel)

				if cfg.OpenID.Provider != config.ProviderIDPorten {
					r.Get(paths.LogoutLocal, src.LogoutLocal)
					r.Head(paths.LogoutLocal, src.LogoutLocal)
				}

				r.Get(paths.Ping, func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("pong"))
				})

				r.Route(paths.Session, func(r chi.Router) {
					if cfg.SSO.IsServer() {
						r.Use(cors(http.MethodGet, http.MethodPost))
						// Cors middleware is designed to be used as a top-level middleware on the chi router.
						// Applying with within a r.Group() or using With() will not work without routes matching OPTIONS added.

						r.Options("/", noopHandler)
						r.Options(paths.Refresh, noopHandler)
					}

					r.Get("/", src.Session)
					r.Get(paths.Refresh, src.SessionRefresh)
					r.Post(paths.Refresh, src.SessionRefresh)
					r.Get(paths.ForwardAuth, src.SessionForwardAuth)
				})
			})
		}

		if cfg.SSO.IsServer() {
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, paths.OAuth2+paths.Login, http.StatusFound)
			})
		}
	})

	r.HandleFunc("/*", src.Wildcard)
	return r
}
