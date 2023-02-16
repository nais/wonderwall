package handler

import (
	"fmt"
	"net/http"
	urllib "net/url"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/ingress"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/router/paths"
	"github.com/nais/wonderwall/pkg/url"
)

var _ router.Source = &SSOProxy{}

type SSOProxy struct {
	Config                *config.Config
	Ingresses             *ingress.Ingresses
	Redirect              url.Redirect
	SSOServerURL          *urllib.URL
	SSOServerReverseProxy *ReverseProxy
}

func NewSSOProxy(cfg *config.Config) (*SSOProxy, error) {
	ingresses, err := ingress.ParseIngresses(cfg)
	if err != nil {
		return nil, err
	}

	u, err := urllib.ParseRequestURI(cfg.SSO.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parsing sso server url: %w", err)
	}

	query := u.Query()

	if len(cfg.OpenID.ACRValues) > 0 {
		query.Set(openidclient.SecurityLevelURLParameter, cfg.OpenID.ACRValues)
	}

	if len(cfg.OpenID.UILocales) > 0 {
		query.Set(openidclient.LocaleURLParameter, cfg.OpenID.UILocales)
	}

	u.RawQuery = query.Encode()

	return &SSOProxy{
		Config:                cfg,
		Ingresses:             ingresses,
		Redirect:              url.NewSSOProxyRedirect(ingresses),
		SSOServerURL:          u,
		SSOServerReverseProxy: NewReverseProxy(u, false),
	}, nil
}

func (s *SSOProxy) Login(w http.ResponseWriter, r *http.Request) {
	logger := logentry.LogEntryFrom(r)

	target := s.GetSSOServerURL()
	targetQuery := target.Query()

	// override default query parameters
	reqQuery := r.URL.Query()
	if reqQuery.Has(openidclient.SecurityLevelURLParameter) {
		targetQuery.Set(openidclient.SecurityLevelURLParameter, reqQuery.Get(openidclient.SecurityLevelURLParameter))
	}
	if reqQuery.Has(openidclient.LocaleURLParameter) {
		targetQuery.Set(openidclient.LocaleURLParameter, reqQuery.Get(openidclient.LocaleURLParameter))
	}

	target.RawQuery = reqQuery.Encode()

	canonicalRedirect := s.GetRedirect().Canonical(r)
	ssoServerLoginURL := url.Login(target, canonicalRedirect)

	logger.WithFields(log.Fields{
		"redirect_to":          ssoServerLoginURL,
		"redirect_after_login": canonicalRedirect,
	}).Info("login: redirecting to sso server")

	http.Redirect(w, r, ssoServerLoginURL, http.StatusTemporaryRedirect)
}

func (s *SSOProxy) LoginCallback(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (s *SSOProxy) Logout(w http.ResponseWriter, r *http.Request) {
	target := s.SSOServerURL.JoinPath(paths.OAuth2, paths.Logout)
	http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
}

func (s *SSOProxy) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (s *SSOProxy) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (s *SSOProxy) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	target := s.SSOServerURL.JoinPath(paths.OAuth2, paths.LogoutLocal)
	http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
}

func (s *SSOProxy) Session(w http.ResponseWriter, r *http.Request) {
	s.SSOServerReverseProxy.ServeHTTP(w, r)
}

func (s *SSOProxy) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	s.SSOServerReverseProxy.ServeHTTP(w, r)
}

func (s *SSOProxy) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	// TODO implement me
	panic("implement me")
}

func (s *SSOProxy) GetIngresses() *ingress.Ingresses {
	return s.Ingresses
}

func (s *SSOProxy) GetRedirect() url.Redirect {
	return s.Redirect
}

func (s *SSOProxy) GetSSOServerURL() *urllib.URL {
	u := *s.SSOServerURL
	return &u
}
