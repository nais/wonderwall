package redirect

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

type Handler interface {
	// Canonical constructs a redirect URL that points back to the application.
	Canonical(r *http.Request) string
	// Clean parses and cleans a target URL according to implementation-specific validations. It should always return a fallback URL string, regardless of validation errors.
	Clean(r *http.Request, target string) string
}

var _ Handler = &DefaultHandler{}

type DefaultHandler struct {
	ingresses *ingress.Ingresses
	validator *Validator
}

func NewDefaultHandler(ingresses *ingress.Ingresses) *DefaultHandler {
	return &DefaultHandler{
		ingresses: ingresses,
		validator: NewValidator(Relative, ingresses.Hosts()),
	}
}

func (h *DefaultHandler) Canonical(r *http.Request) string {
	target := redirectQueryParam(r)
	redirect, err := url.ParseRequestURI(target)
	if err != nil {
		redirect = fallback(r, target, h.FallbackRedirect(r))
	}

	// redirect must be a relative URL to avoid cross-domain redirects
	redirect.Scheme = ""
	redirect.Host = ""

	return h.Clean(r, redirect.String())
}

func (h *DefaultHandler) Clean(r *http.Request, target string) string {
	if h.validator.IsValidRedirect(r, target) {
		return target
	}

	return fallback(r, target, h.FallbackRedirect(r)).String()
}

func (h *DefaultHandler) FallbackRedirect(r *http.Request) *url.URL {
	return urlpkg.MatchingPath(r)
}

var _ Handler = &SSOServerHandler{}

type SSOServerHandler struct {
	fallbackRedirect *url.URL
	validator        *Validator
}

func NewSSOServerHandler(config *config.Config) (*SSOServerHandler, error) {
	u, err := url.ParseRequestURI(config.SSO.ServerDefaultRedirectURL)
	if err != nil {
		return nil, fmt.Errorf("parsing fallback redirect URL: %w", err)
	}

	return &SSOServerHandler{
		fallbackRedirect: u,
		validator:        NewValidator(Absolute, []string{config.SSO.Domain}),
	}, nil
}

func (h *SSOServerHandler) Canonical(r *http.Request) string {
	target := redirectQueryParam(r)
	redirect, err := url.ParseRequestURI(target)
	if err != nil {
		redirect = fallback(r, target, h.fallbackRedirect)
	}

	return h.Clean(r, redirect.String())
}

func (h *SSOServerHandler) Clean(r *http.Request, target string) string {
	if h.validator.IsValidRedirect(r, target) {
		return target
	}

	return fallback(r, target, h.fallbackRedirect).String()
}

var _ Handler = &SSOProxyHandler{}

type SSOProxyHandler struct {
	fallbackRedirect *url.URL
	validator        *Validator
}

func NewSSOProxyHandler(ingresses *ingress.Ingresses) *SSOProxyHandler {
	return &SSOProxyHandler{
		fallbackRedirect: ingresses.Single().NewURL(),
		validator:        NewValidator(Absolute, ingresses.Hosts()),
	}
}

func (h *SSOProxyHandler) Canonical(r *http.Request) string {
	// find matching request ingress, use as base redirect
	redirect, err := urlpkg.MatchingIngress(r)
	if err != nil {
		redirect = h.getFallbackRedirect()
	}

	// get redirect from request query parameter
	target := redirectQueryParam(r)
	redirectParamURL, err := url.ParseRequestURI(target)
	if err != nil {
		logInvalidRedirect(r, target, redirect.String())
	} else {
		// copy desired path and query to base redirect
		redirect.Path = redirectParamURL.Path
		redirect.RawQuery = redirectParamURL.RawQuery
	}

	return h.Clean(r, redirect.String())
}

func (h *SSOProxyHandler) Clean(r *http.Request, target string) string {
	if h.validator.IsValidRedirect(r, target) {
		return target
	}

	return fallback(r, target, h.getFallbackRedirect()).String()
}

// getFallbackRedirect returns a copy of the configured fallbackRedirect
func (h *SSOProxyHandler) getFallbackRedirect() *url.URL {
	u := *h.fallbackRedirect
	return &u
}

func redirectQueryParam(r *http.Request) string {
	return r.URL.Query().Get(urlpkg.RedirectQueryParameter)
}

func fallback(r *http.Request, target string, fallback *url.URL) *url.URL {
	logInvalidRedirect(r, target, fallback.String())
	return fallback
}

func logInvalidRedirect(r *http.Request, target, fallback string) {
	if target == "" {
		mw.LogEntryFrom(r).Infof("redirect: empty target; falling back to %q", fallback)
	} else {
		mw.LogEntryFrom(r).Infof("redirect: rejecting invalid target %q; falling back to %q", target, fallback)
	}
}
