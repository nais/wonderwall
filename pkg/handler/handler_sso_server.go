package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/redirect"
	"github.com/nais/wonderwall/pkg/router"
)

var _ router.Source = &SSOServerHandler{}

type SSOServerHandler struct {
	DefaultHandler
}

func NewSSOServerHandler(handler *DefaultHandler) (*SSOServerHandler, error) {
	rdHandler, err := redirect.NewSSOServerHandler(handler.Config)
	if err != nil {
		return nil, err
	}
	handler.RedirectHandler = rdHandler
	return &SSOServerHandler{DefaultHandler: *handler}, nil
}

func (s *SSOServerHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie.ClearLegacyCookies(w, s.GetCookieOptions())
	s.DefaultHandler.Logout(w, r)
}

func (s *SSOServerHandler) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	cookie.ClearLegacyCookies(w, s.GetCookieOptions())
	s.DefaultHandler.LogoutFrontChannel(w, r)
}

func (s *SSOServerHandler) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	cookie.ClearLegacyCookies(w, s.GetCookieOptions())
	s.DefaultHandler.LogoutLocal(w, r)
}

func (s *SSOServerHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
