package handler

import (
	"fmt"
	"net/http"
	urllib "net/url"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/router/paths"
)

var _ router.Source = &SSOProxyHandler{}

type SSOProxyHandler struct {
	Config       *config.Config
	Ingresses    *ingress.Ingresses
	SSOServerURL *urllib.URL
}

func NewSSOProxyHandler(cfg *config.Config) (*SSOProxyHandler, error) {
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

	return &SSOProxyHandler{
		Config:       cfg,
		Ingresses:    ingresses,
		SSOServerURL: u,
	}, nil
}

func (s *SSOProxyHandler) Login(w http.ResponseWriter, r *http.Request) {
	target := *s.SSOServerURL
	targetQuery := target.Query()

	reqQuery := r.URL.Query()

	if reqQuery.Has(openidclient.SecurityLevelURLParameter) {
		targetQuery.Set(openidclient.SecurityLevelURLParameter, reqQuery.Get(openidclient.SecurityLevelURLParameter))
	}

	if reqQuery.Has(openidclient.LocaleURLParameter) {
		targetQuery.Set(openidclient.LocaleURLParameter, reqQuery.Get(openidclient.LocaleURLParameter))
	}

	target.RawQuery = reqQuery.Encode()

	redirect, err := url.Ingress(r)
	if err != nil {
		redirect = s.Ingresses.Single().NewURL()
	}
	parsedRedirect, err := urllib.ParseRequestURI(reqQuery.Get(url.RedirectURLParameter))
	if err == nil {
		redirect = redirect.JoinPath(parsedRedirect.Path)
	}

	ssoServerLoginURL := url.Login(&target, redirect.String())

	mw.LogEntryFrom(r).
		WithFields(log.Fields{
			"redirect_to":          ssoServerLoginURL,
			"redirect_after_login": redirect.String(),
		}).
		Info("login: redirecting to sso server")

	http.Redirect(w, r, ssoServerLoginURL, http.StatusTemporaryRedirect)
}

func (s *SSOProxyHandler) LoginCallback(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (s *SSOProxyHandler) Logout(w http.ResponseWriter, r *http.Request) {
	target := s.SSOServerURL.JoinPath(paths.OAuth2, paths.Logout)
	http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
}

func (s *SSOProxyHandler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (s *SSOProxyHandler) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (s *SSOProxyHandler) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	target := s.SSOServerURL.JoinPath(paths.OAuth2, paths.LogoutLocal)
	http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
}

func (s *SSOProxyHandler) Session(w http.ResponseWriter, r *http.Request) {
	// TODO proxy to sso-server or use session handler that fetches directly from session store)
	panic("implement me")
}

func (s *SSOProxyHandler) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	// TODO proxy to sso-server
	panic("implement me")
}

func (s *SSOProxyHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	// TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) GetIngresses() *ingress.Ingresses {
	return s.Ingresses
}
