package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/url"
)

var _ router.Source = &SSOServer{}

type SSOServer struct {
	*Standalone
}

func NewSSOServer(handler *Standalone) (*SSOServer, error) {
	redirect, err := url.NewSSOServerRedirect(handler.Config)
	if err != nil {
		return nil, err
	}

	handler.Redirect = redirect
	return &SSOServer{Standalone: handler}, nil
}

func (s *SSOServer) Logout(w http.ResponseWriter, r *http.Request) {
	cookie.ClearLegacyCookies(w, s.GetCookieOptions(r))
	s.Standalone.Logout(w, r)
}

func (s *SSOServer) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	cookie.ClearLegacyCookies(w, s.GetCookieOptions(r))
	s.Standalone.LogoutFrontChannel(w, r)
}

func (s *SSOServer) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	cookie.ClearLegacyCookies(w, s.GetCookieOptions(r))
	s.Standalone.LogoutLocal(w, r)
}

func (s *SSOServer) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.Config.SSO.ServerDefaultRedirectURL, http.StatusTemporaryRedirect)
}
