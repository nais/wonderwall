package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/url"
)

var _ router.Source = &SSOServer{}

type SSOServer struct {
	*Standalone
}

func NewSSOServer(cfg *config.Config, handler *Standalone) (*SSOServer, error) {
	redirect, err := url.NewSSOServerRedirect(cfg)
	if err != nil {
		return nil, err
	}

	handler.Redirect = redirect
	handler.CookieOptions = cookie.DefaultOptions().
		WithPath("/").
		WithDomain(cfg.SSO.Domain).
		WithSameSite(cfg.Cookie.SameSite.ToHttp()).
		WithSecure(cfg.Cookie.Secure)

	return &SSOServer{Standalone: handler}, nil
}

// Wildcard redirects unhandled requests to the default redirect URL.
func (s *SSOServer) Wildcard(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.Config.SSO.ServerDefaultRedirectURL, http.StatusFound)
}
