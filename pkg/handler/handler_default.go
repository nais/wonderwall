package handler

import (
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	errorhandler "github.com/nais/wonderwall/pkg/handler/error"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/redirect"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

var _ router.Source = &DefaultHandler{}

type DefaultHandler struct {
	AutoLogin       *autologin.AutoLogin
	Client          *openidclient.Client
	Config          *config.Config
	CookieOptions   cookie.Options
	Crypter         crypto.Crypter
	Ingresses       *ingress.Ingresses
	OpenidConfig    openidconfig.Config
	RedirectHandler redirect.Handler
	Sessions        *session.Handler
	UpstreamProxy   *ReverseProxy
}

func NewDefaultHandler(
	cfg *config.Config,
	cookieOpts cookie.Options,
	jwksProvider openidclient.JwksProvider,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
) (*DefaultHandler, error) {
	autoLogin, err := autologin.New(cfg)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	openidClient := openidclient.NewClient(openidConfig, jwksProvider)
	openidClient.SetHttpClient(httpClient)

	sessionHandler, err := session.NewHandler(cfg, openidConfig, crypter, openidClient)
	if err != nil {
		return nil, err
	}

	ingresses, err := ingress.ParseIngresses(cfg)
	if err != nil {
		return nil, err
	}

	redirectHandler := redirect.NewDefaultHandler(ingresses)

	return &DefaultHandler{
		AutoLogin:       autoLogin,
		Client:          openidClient,
		Config:          cfg,
		CookieOptions:   cookieOpts,
		Crypter:         crypter,
		Ingresses:       ingresses,
		OpenidConfig:    openidConfig,
		Sessions:        sessionHandler,
		UpstreamProxy:   NewReverseProxy(cfg.UpstreamHost),
		RedirectHandler: redirectHandler,
	}, nil
}

func (d *DefaultHandler) GetAutoLogin() *autologin.AutoLogin {
	return d.AutoLogin
}

func (d *DefaultHandler) GetClient() *openidclient.Client {
	return d.Client
}

func (d *DefaultHandler) GetCookieOptions() cookie.Options {
	return d.CookieOptions
}

func (d *DefaultHandler) GetCookieOptsPathAware(r *http.Request) cookie.Options {
	if d.Config.SSO.Enabled {
		return d.GetCookieOptions()
	}

	path := d.GetPath(r)
	return d.CookieOptions.WithPath(path)
}

func (d *DefaultHandler) GetCrypter() crypto.Crypter {
	return d.Crypter
}

func (d *DefaultHandler) GetErrorHandler() errorhandler.Handler {
	return errorhandler.New(d)
}

func (d *DefaultHandler) GetIngresses() *ingress.Ingresses {
	return d.Ingresses
}

func (d *DefaultHandler) GetPath(r *http.Request) string {
	path, ok := middleware.PathFrom(r.Context())
	if !ok {
		path = d.Ingresses.MatchingPath(r)
	}

	return path
}

func (d *DefaultHandler) GetRedirectHandler() redirect.Handler {
	return d.RedirectHandler
}

func (d *DefaultHandler) GetSessions() *session.Handler {
	return d.Sessions
}

func (d *DefaultHandler) GetSessionConfig() config.Session {
	return d.Config.Session
}

func (d *DefaultHandler) Login(w http.ResponseWriter, r *http.Request) {
	Login(d, w, r)
}

func (d *DefaultHandler) LoginCallback(w http.ResponseWriter, r *http.Request) {
	LoginCallback(d, w, r)
}

func (d *DefaultHandler) Logout(w http.ResponseWriter, r *http.Request) {
	opts := LogoutOptions{
		GlobalLogout: true,
	}
	Logout(d, w, r, opts)
}

func (d *DefaultHandler) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	opts := LogoutOptions{
		GlobalLogout: false,
	}
	Logout(d, w, r, opts)
}

func (d *DefaultHandler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	LogoutCallback(d, w, r)
}

func (d *DefaultHandler) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	LogoutFrontChannel(d, w, r)
}

func (d *DefaultHandler) Session(w http.ResponseWriter, r *http.Request) {
	Session(d, w, r)
}

func (d *DefaultHandler) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	if !d.Config.Session.Refresh {
		http.NotFound(w, r)
		return
	}

	SessionRefresh(d, w, r)
}

func (d *DefaultHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	d.UpstreamProxy.Handler(d, w, r)
}
