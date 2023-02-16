package handler

import (
	"net/http"
	urllib "net/url"
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
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/url"
)

var _ router.Source = &Standalone{}

type Standalone struct {
	AutoLogin     *autologin.AutoLogin
	Client        *openidclient.Client
	Config        *config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Ingresses     *ingress.Ingresses
	OpenidConfig  openidconfig.Config
	Redirect      url.Redirect
	Sessions      *session.Handler
	UpstreamProxy *ReverseProxy
}

func NewStandalone(
	cfg *config.Config,
	cookieOpts cookie.Options,
	jwksProvider openidclient.JwksProvider,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
) (*Standalone, error) {
	autoLogin, err := autologin.New(cfg)
	if err != nil {
		return nil, err
	}

	openidClient := openidclient.NewClient(openidConfig, jwksProvider)
	openidClient.SetHttpClient(&http.Client{
		Timeout: time.Second * 10,
	})

	sessionHandler, err := session.NewHandler(cfg, openidConfig, crypter, openidClient)
	if err != nil {
		return nil, err
	}

	ingresses, err := ingress.ParseIngresses(cfg)
	if err != nil {
		return nil, err
	}

	upstream := &urllib.URL{
		Host:   cfg.UpstreamHost,
		Scheme: "http",
	}

	return &Standalone{
		AutoLogin:     autoLogin,
		Client:        openidClient,
		Config:        cfg,
		CookieOptions: cookieOpts,
		Crypter:       crypter,
		Ingresses:     ingresses,
		OpenidConfig:  openidConfig,
		Redirect:      url.NewStandaloneRedirect(ingresses),
		Sessions:      sessionHandler,
		UpstreamProxy: NewReverseProxy(upstream, true),
	}, nil
}

func (s *Standalone) GetAutoLogin() *autologin.AutoLogin {
	return s.AutoLogin
}

func (s *Standalone) GetClient() *openidclient.Client {
	return s.Client
}

func (s *Standalone) GetCookieOptions() cookie.Options {
	return s.CookieOptions
}

func (s *Standalone) GetCookieOptsPathAware(r *http.Request) cookie.Options {
	if s.Config.SSO.Enabled {
		return s.GetCookieOptions()
	}

	path := s.GetPath(r)
	return s.CookieOptions.WithPath(path)
}

func (s *Standalone) GetCrypter() crypto.Crypter {
	return s.Crypter
}

func (s *Standalone) GetErrorHandler() errorhandler.Handler {
	return errorhandler.New(s)
}

func (s *Standalone) GetIngresses() *ingress.Ingresses {
	return s.Ingresses
}

func (s *Standalone) GetPath(r *http.Request) string {
	path, ok := middleware.PathFrom(r.Context())
	if !ok {
		path = s.Ingresses.MatchingPath(r)
	}

	return path
}

func (s *Standalone) GetRedirect() url.Redirect {
	return s.Redirect
}

func (s *Standalone) GetSessions() *session.Handler {
	return s.Sessions
}

func (s *Standalone) GetSessionConfig() config.Session {
	return s.Config.Session
}

func (s *Standalone) Login(w http.ResponseWriter, r *http.Request) {
	Login(s, w, r)
}

func (s *Standalone) LoginCallback(w http.ResponseWriter, r *http.Request) {
	LoginCallback(s, w, r)
}

func (s *Standalone) Logout(w http.ResponseWriter, r *http.Request) {
	opts := LogoutOptions{
		GlobalLogout: true,
	}
	Logout(s, w, r, opts)
}

func (s *Standalone) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	opts := LogoutOptions{
		GlobalLogout: false,
	}
	Logout(s, w, r, opts)
}

func (s *Standalone) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	LogoutCallback(s, w, r)
}

func (s *Standalone) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	LogoutFrontChannel(s, w, r)
}

func (s *Standalone) Session(w http.ResponseWriter, r *http.Request) {
	Session(s, w, r)
}

func (s *Standalone) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.Config.Session.Refresh {
		http.NotFound(w, r)
		return
	}

	SessionRefresh(s, w, r)
}

func (s *Standalone) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	s.UpstreamProxy.Handler(s, w, r)
}
