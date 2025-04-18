package handler

import (
	"fmt"
	"net/http"
	urllib "net/url"

	"github.com/nais/wonderwall/internal/o11y/otel"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/handler/acr"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/router/paths"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/url"
)

var _ router.Source = &SSOProxy{}

type SSOProxy struct {
	AcrHandler            *acr.Handler
	AutoLogin             *autologin.AutoLogin
	Config                *config.Config
	Ingresses             *ingress.Ingresses
	Redirect              url.Redirect
	SSOServerURL          *urllib.URL
	SSOServerReverseProxy *ReverseProxy
	SessionReader         session.Reader
	UpstreamProxy         *ReverseProxy
}

func NewSSOProxy(cfg *config.Config, crypter crypto.Crypter) (*SSOProxy, error) {
	autoLogin, err := autologin.New(cfg)
	if err != nil {
		return nil, err
	}

	ingresses, err := ingress.ParseIngresses(cfg)
	if err != nil {
		return nil, err
	}

	sessionReader, err := session.NewReader(cfg, crypter)
	if err != nil {
		return nil, err
	}

	serverURL, err := urllib.ParseRequestURI(cfg.SSO.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parsing sso server url: %w", err)
	}

	upstream := &urllib.URL{
		Host:   cfg.UpstreamHost,
		Scheme: "http",
	}

	return &SSOProxy{
		AcrHandler:            acr.NewHandler(cfg),
		AutoLogin:             autoLogin,
		Config:                cfg,
		Ingresses:             ingresses,
		Redirect:              url.NewSSOProxyRedirect(ingresses),
		SSOServerURL:          serverURL,
		SSOServerReverseProxy: NewReverseProxy(serverURL, false),
		SessionReader:         sessionReader,
		UpstreamProxy:         NewUpstreamProxy(upstream, cfg.UpstreamAccessLogs, cfg.UpstreamIncludeIdToken),
	}, nil
}

func (s *SSOProxy) GetAcrHandler() *acr.Handler {
	return s.AcrHandler
}

func (s *SSOProxy) GetAutoLogin() *autologin.AutoLogin {
	return s.AutoLogin
}

func (s *SSOProxy) GetIngresses() *ingress.Ingresses {
	return s.Ingresses
}

func (s *SSOProxy) GetPath(r *http.Request) string {
	return GetPath(r, s.GetIngresses())
}

func (s *SSOProxy) GetSession(r *http.Request) (*session.Session, error) {
	return s.SessionReader.Get(r)
}

func (s *SSOProxy) GetSSOServerURL() *urllib.URL {
	u := *s.SSOServerURL
	return &u
}

func (s *SSOProxy) Login(w http.ResponseWriter, r *http.Request) {
	r, span := otel.StartSpanFromRequest(r, "Login")
	defer span.End()
	logger := mw.LogEntryFrom(r)

	target := s.GetSSOServerURL()
	span.SetAttributes(attribute.String("login.redirect_to", target.String()))
	targetQuery := target.Query()

	// set default query parameters
	if len(s.Config.OpenID.ACRValues) > 0 {
		targetQuery.Set(openidclient.QueryParamSecurityLevel, s.Config.OpenID.ACRValues)
	}
	if len(s.Config.OpenID.UILocales) > 0 {
		targetQuery.Set(openidclient.QueryParamLocale, s.Config.OpenID.UILocales)
	}

	// override default query parameters, if provided in request
	reqQuery := r.URL.Query()
	if reqQuery.Has(openidclient.QueryParamSecurityLevel) {
		targetQuery.Set(openidclient.QueryParamSecurityLevel, reqQuery.Get(openidclient.QueryParamSecurityLevel))
		span.SetAttributes(attribute.String("login.level", reqQuery.Get(openidclient.QueryParamSecurityLevel)))
	}
	if reqQuery.Has(openidclient.QueryParamLocale) {
		targetQuery.Set(openidclient.QueryParamLocale, reqQuery.Get(openidclient.QueryParamLocale))
		span.SetAttributes(attribute.String("login.locale", reqQuery.Get(openidclient.QueryParamLocale)))
	}
	if reqQuery.Has(openidclient.QueryParamPrompt) {
		targetQuery.Set(openidclient.QueryParamPrompt, reqQuery.Get(openidclient.QueryParamPrompt))
		span.SetAttributes(attribute.String("login.prompt", reqQuery.Get(openidclient.QueryParamPrompt)))
	}

	target.RawQuery = targetQuery.Encode()

	canonicalRedirect := s.Redirect.Canonical(r)
	ssoServerLoginURL := url.Login(target, canonicalRedirect)

	logger.WithFields(log.Fields{
		"redirect_to":          ssoServerLoginURL,
		"redirect_after_login": canonicalRedirect,
	}).Info("login: redirecting to sso server")
	span.SetAttributes(attribute.String("login.redirect_after", canonicalRedirect))

	http.Redirect(w, r, ssoServerLoginURL, http.StatusFound)
}

func (s *SSOProxy) LoginCallback(w http.ResponseWriter, r *http.Request) {
	ingressPath := s.GetPath(r)
	login := url.LoginRelative(ingressPath, ingressPath)
	http.Redirect(w, r, login, http.StatusFound)
}

func (s *SSOProxy) Logout(w http.ResponseWriter, r *http.Request) {
	r, span := otel.StartSpanFromRequest(r, "Logout")
	defer span.End()
	target := s.GetSSOServerURL()

	// only set a canonical redirect if it was provided in the request as a query parameter
	canonicalRedirect := r.URL.Query().Get(url.RedirectQueryParameter)
	if canonicalRedirect != "" {
		canonicalRedirect = s.Redirect.Canonical(r)
	}
	ssoServerLogoutURL := url.Logout(target, canonicalRedirect)

	mw.LogEntryFrom(r).WithFields(log.Fields{
		"redirect_to":           ssoServerLogoutURL,
		"redirect_after_logout": canonicalRedirect,
	}).Info("logout: redirecting to sso server")
	span.SetAttributes(attribute.String("logout.redirect_to", target.String()))
	span.SetAttributes(attribute.String("logout.redirect_after", canonicalRedirect))

	http.Redirect(w, r, ssoServerLogoutURL, http.StatusFound)
}

func (s *SSOProxy) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	target := s.GetSSOServerURL().JoinPath(paths.OAuth2, paths.Logout)
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *SSOProxy) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = paths.OAuth2 + paths.LogoutFrontChannel
	removeMiddlewareHeaders(w)
	s.SSOServerReverseProxy.ServeHTTP(w, r)
}

func (s *SSOProxy) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = paths.OAuth2 + paths.LogoutLocal
	removeMiddlewareHeaders(w)
	s.SSOServerReverseProxy.ServeHTTP(w, r)
}

func (s *SSOProxy) Session(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = paths.OAuth2 + paths.Session
	removeMiddlewareHeaders(w)
	s.SSOServerReverseProxy.ServeHTTP(w, r)
}

func (s *SSOProxy) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = paths.OAuth2 + paths.Session + paths.Refresh
	removeMiddlewareHeaders(w)
	s.SSOServerReverseProxy.ServeHTTP(w, r)
}

func (s *SSOProxy) SessionForwardAuth(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = paths.OAuth2 + paths.Session + paths.ForwardAuth
	removeMiddlewareHeaders(w)
	s.SSOServerReverseProxy.ServeHTTP(w, r)
}

// Wildcard proxies all requests to an upstream server.
func (s *SSOProxy) Wildcard(w http.ResponseWriter, r *http.Request) {
	s.UpstreamProxy.Handler(s, w, r)
}

// removeMiddlewareHeaders removes known headers added by the router middlewares.
// These headers are already set by the very same middlewares at the SSO server.
// This avoids duplicate response headers when using [httputil.ReverseProxy] which uses [http.Header.Add] instead of [http.Header.Set] when copying headers from the upstream response.
func removeMiddlewareHeaders(w http.ResponseWriter) {
	headers := []string{
		// added by [chi_middleware.NoCache]
		"Expires", "Cache-Control", "Pragma", "X-Accel-Expires",
		// added by [middleware.Cors]
		"Vary",
	}
	for _, header := range headers {
		w.Header().Del(header)
	}
}
