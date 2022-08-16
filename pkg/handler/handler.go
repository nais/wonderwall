package handler

import (
	"context"
	"net/http"
	"net/http/httputil"

	"github.com/nais/wonderwall/pkg/autologin"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/provider"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	AutoLogin     *autologin.Options
	Client        client.Client
	Config        *config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Loginstatus   loginstatus.Loginstatus
	OpenIDConfig  openidconfig.Config
	Provider      provider.Provider
	ReverseProxy  *httputil.ReverseProxy
	Sessions      session.Store

	path string
}

func NewHandler(
	ctx context.Context,
	cfg *config.Config,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
	sessionStore session.Store,
) (*Handler, error) {
	openidProvider, err := provider.NewProvider(ctx, openidConfig)
	if err != nil {
		return nil, err
	}

	autoLogin, err := autologin.NewOptions(cfg)
	if err != nil {
		return nil, err
	}

	return &Handler{
		AutoLogin:     autoLogin,
		Client:        client.NewClient(openidConfig),
		Config:        cfg,
		CookieOptions: cookie.DefaultOptions().WithPath(config.ParseIngress(cfg.Ingress)),
		Crypter:       crypter,
		Loginstatus:   loginstatus.NewClient(cfg.Loginstatus, http.DefaultClient),
		OpenIDConfig:  openidConfig,
		Provider:      openidProvider,
		ReverseProxy:  newReverseProxy(cfg.UpstreamHost),
		Sessions:      sessionStore,
		path:          config.ParseIngress(cfg.Ingress),
	}, nil
}

func newReverseProxy(upstreamHost string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// Delete incoming authentication
			r.Header.Del("authorization")
			// Instruct http.ReverseProxy to not modify X-Forwarded-For header
			r.Header["X-Forwarded-For"] = nil
			// Request should go to correct host
			r.URL.Host = upstreamHost
			r.URL.Scheme = "http"

			accessToken, ok := middleware.AccessTokenFrom(r.Context())
			if ok {
				r.Header.Set("authorization", "Bearer "+accessToken)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}
}

func (h *Handler) Path() string {
	return h.path
}
