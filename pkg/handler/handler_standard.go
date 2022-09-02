package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	apilogin "github.com/nais/wonderwall/pkg/handler/api/login"
	apilogincallback "github.com/nais/wonderwall/pkg/handler/api/logincallback"
	apilogout "github.com/nais/wonderwall/pkg/handler/api/logout"
	apilogoutcallback "github.com/nais/wonderwall/pkg/handler/api/logoutcallback"
	apilogoutfrontchannel "github.com/nais/wonderwall/pkg/handler/api/logoutfrontchannel"
	apisession "github.com/nais/wonderwall/pkg/handler/api/session"
	apisessionrefresh "github.com/nais/wonderwall/pkg/handler/api/sessionrefresh"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	errorhandler "github.com/nais/wonderwall/pkg/handler/error"
	"github.com/nais/wonderwall/pkg/handler/reverseproxy"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
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
	provider      openidclient.OpenIDProvider
	sessions      *session.Handler
	upstreamProxy *reverseproxy.ReverseProxy
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

func (s *StandardHandler) GetErrorRedirectURI() string {
	return s.config.ErrorRedirectURI
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

func (s *StandardHandler) GetProvider() openidclient.OpenIDProvider {
	return s.provider
}

func (s *StandardHandler) GetProviderName() string {
	return s.openidConfig.Provider().Name()
}

func (s *StandardHandler) GetSessions() *session.Handler {
	return s.sessions
}

func (s *StandardHandler) GetSessionConfig() config.Session {
	return s.config.Session
}

func (s *StandardHandler) Login(w http.ResponseWriter, r *http.Request) {
	apilogin.Handler(s, w, r)
}

func (s *StandardHandler) LoginCallback(w http.ResponseWriter, r *http.Request) {
	apilogincallback.Handler(s, w, r)
}

func (s *StandardHandler) Logout(w http.ResponseWriter, r *http.Request) {
	apilogout.Handler(s, w, r)
}

func (s *StandardHandler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	apilogoutcallback.Handler(s, w, r)
}

func (s *StandardHandler) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	apilogoutfrontchannel.Handler(s, w, r)
}

func (s *StandardHandler) Session(w http.ResponseWriter, r *http.Request) {
	apisession.Handler(s, w, r)
}

func (s *StandardHandler) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.config.Session.Refresh {
		http.NotFound(w, r)
		return
	}

	apisessionrefresh.Handler(s, w, r)
}

func (s *StandardHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	s.upstreamProxy.Handler(s, w, r)
}
