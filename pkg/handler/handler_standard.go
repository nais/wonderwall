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
	autoLogin     *autologin.AutoLogin
	client        *openidclient.Client
	config        *config.Config
	cookieOptions cookie.Options
	crypter       crypto.Crypter
	ingresses     *ingress.Ingresses
	loginstatus   *loginstatus.Loginstatus
	openidConfig  openidconfig.Config
	sessions      *sessionStore.Handler
	upstreamProxy *ReverseProxy
}

func (s *StandardHandler) GetAutoLogin() *autologin.AutoLogin {
	return s.autoLogin
}

func (s *StandardHandler) GetClient() *openidclient.Client {
	return s.client
}

func (s *StandardHandler) GetCookieOptions() cookie.Options {
	return s.cookieOptions
}

func (s *StandardHandler) GetCookieOptsPathAware(r *http.Request) cookie.Options {
	path := s.GetPath(r)
	return s.cookieOptions.WithPath(path)
}

func (s *StandardHandler) GetCrypter() crypto.Crypter {
	return s.crypter
}

func (s *StandardHandler) GetErrorHandler() errorhandler.Handler {
	return errorhandler.New(s)
}

func (s *StandardHandler) GetErrorPath() string {
	return s.config.ErrorPath
}

func (s *StandardHandler) GetIngresses() *ingress.Ingresses {
	return s.ingresses
}

func (s *StandardHandler) SetIngresses(ingresses *ingress.Ingresses) {
	s.ingresses = ingresses
}

func (s *StandardHandler) GetLoginstatus() *loginstatus.Loginstatus {
	return s.loginstatus
}

func (s *StandardHandler) GetPath(r *http.Request) string {
	path, ok := middleware.PathFrom(r.Context())
	if !ok {
		path = s.GetIngresses().MatchingPath(r)
	}

	return path
}

func (s *StandardHandler) GetProviderName() string {
	return string(s.config.OpenID.Provider)
}

func (s *StandardHandler) GetSessions() *sessionStore.Handler {
	return s.sessions
}

func (s *StandardHandler) GetSessionConfig() config.Session {
	return s.config.Session
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
	if !s.config.Session.Refresh {
		http.NotFound(w, r)
		return
	}

	SessionRefresh(s, w, r)
}

func (s *StandardHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	s.upstreamProxy.Handler(s, w, r)
}
