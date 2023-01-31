package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	errorhandler "github.com/nais/wonderwall/pkg/handler/error"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/router"
	sessionStore "github.com/nais/wonderwall/pkg/session"
)

var _ router.Source = &StandardHandler{}

type StandardHandler struct {
	AutoLogin     *autologin.AutoLogin
	Client        *openidclient.Client
	Config        *config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Ingresses     *ingress.Ingresses
	Loginstatus   *loginstatus.Loginstatus
	OpenidConfig  openidconfig.Config
	Sessions      *sessionStore.Handler
	UpstreamProxy *ReverseProxy
}

func (s *StandardHandler) GetAutoLogin() *autologin.AutoLogin {
	return s.AutoLogin
}

func (s *StandardHandler) GetClient() *openidclient.Client {
	return s.Client
}

func (s *StandardHandler) GetCookieOptions() cookie.Options {
	return s.CookieOptions
}

func (s *StandardHandler) GetCookieOptsPathAware(r *http.Request) cookie.Options {
	path := s.GetPath(r)
	return s.CookieOptions.WithPath(path)
}

func (s *StandardHandler) GetCrypter() crypto.Crypter {
	return s.Crypter
}

func (s *StandardHandler) GetErrorHandler() errorhandler.Handler {
	return errorhandler.New(s)
}

func (s *StandardHandler) GetErrorPath() string {
	return s.Config.ErrorPath
}

func (s *StandardHandler) GetIngresses() *ingress.Ingresses {
	return s.Ingresses
}

func (s *StandardHandler) GetLoginstatus() *loginstatus.Loginstatus {
	return s.Loginstatus
}

func (s *StandardHandler) GetPath(r *http.Request) string {
	path, ok := middleware.PathFrom(r.Context())
	if !ok {
		path = s.Ingresses.MatchingPath(r)
	}

	return path
}

func (s *StandardHandler) GetSessions() *sessionStore.Handler {
	return s.Sessions
}

func (s *StandardHandler) GetSessionConfig() config.Session {
	return s.Config.Session
}

func (s *StandardHandler) Login(w http.ResponseWriter, r *http.Request) {
	Login(s, w, r)
}

func (s *StandardHandler) LoginCallback(w http.ResponseWriter, r *http.Request) {
	LoginCallback(s, w, r)
}

func (s *StandardHandler) Logout(w http.ResponseWriter, r *http.Request) {
	opts := LogoutOptions{
		GlobalLogout: true,
	}
	Logout(s, w, r, opts)
}

func (s *StandardHandler) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	opts := LogoutOptions{
		GlobalLogout: false,
	}
	Logout(s, w, r, opts)
}

func (s *StandardHandler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	LogoutCallback(s, w, r)
}

func (s *StandardHandler) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	LogoutFrontChannel(s, w, r)
}

func (s *StandardHandler) Session(w http.ResponseWriter, r *http.Request) {
	Session(s, w, r)
}

func (s *StandardHandler) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.Config.Session.Refresh {
		http.NotFound(w, r)
		return
	}

	SessionRefresh(s, w, r)
}

func (s *StandardHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	s.UpstreamProxy.Handler(s, w, r)
}
