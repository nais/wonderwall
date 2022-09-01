package handler

import (
	"context"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/openid/provider"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	AutoLogin     *autologin.AutoLogin
	Client        client.Client
	Config        *config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Loginstatus   loginstatus.Loginstatus
	OpenIDConfig  openidconfig.Config
	Provider      provider.Provider
	ReverseProxy  *httputil.ReverseProxy
	Sessions      *session.Handler
}

func NewHandler(
	ctx context.Context,
	cfg *config.Config,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
) (*Handler, error) {
	openidProvider, err := provider.NewProvider(ctx, openidConfig)
	if err != nil {
		return nil, err
	}

	autoLogin, err := autologin.New(cfg)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	openidClient := client.NewClient(openidConfig)
	openidClient.SetHttpClient(httpClient)

	sessionHandler, err := session.NewHandler(cfg, openidConfig, crypter, openidClient)
	if err != nil {
		return nil, err
	}

	return &Handler{
		AutoLogin:     autoLogin,
		Client:        openidClient,
		Config:        cfg,
		CookieOptions: cookie.DefaultOptions(),
		Crypter:       crypter,
		Loginstatus:   loginstatus.NewClient(cfg.Loginstatus, httpClient),
		OpenIDConfig:  openidConfig,
		Provider:      openidProvider,
		ReverseProxy:  newReverseProxy(cfg.UpstreamHost),
		Sessions:      sessionHandler,
	}, nil
}

func (h *Handler) CookieOptsPathAware(r *http.Request) cookie.Options {
	path := h.Path(r)
	return h.CookieOptions.WithPath(path)
}

func (h *Handler) Ingresses() *ingress.Ingresses {
	return h.OpenIDConfig.Client().Ingresses()
}

func (h *Handler) Path(r *http.Request) string {
	path, ok := middleware.PathFrom(r.Context())
	if !ok {
		path = h.OpenIDConfig.Client().Ingresses().MatchingPath(r)
	}

	return path
}

func (h *Handler) ProviderName() string {
	return h.OpenIDConfig.Provider().Name()
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
