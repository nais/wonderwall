package url

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
)

type Redirect interface {
	// Canonical constructs a redirect URL that points back to the application.
	Canonical(r *http.Request) string
	// Clean parses and cleans a target URL according to implementation-specific validations. It should always return a fallback URL string, regardless of validation errors.
	Clean(r *http.Request, target string) string
	// GetValidator returns the Validator used to Clean URLs.
	GetValidator() Validator
}

var _ Redirect = &StandaloneRedirect{}

type StandaloneRedirect struct {
	*cleaner
}

func NewStandaloneRedirect(ingresses *ingress.Ingresses) *StandaloneRedirect {
	return &StandaloneRedirect{
		cleaner: newRelativeCleaner(ingresses.Hosts()),
	}
}

func (h *StandaloneRedirect) Canonical(r *http.Request) string {
	target := redirectQueryParam(r)
	redirect, err := url.Parse(target)
	if err != nil {
		redirect = fallback(r, target, h.getFallbackRedirect(r))
	}

	// redirect must be a relative URL to avoid cross-domain redirects
	redirect.Scheme = ""
	redirect.Host = ""

	return h.Clean(r, redirect.String())
}

func (h *StandaloneRedirect) Clean(r *http.Request, target string) string {
	return h.clean(r, target, h.getFallbackRedirect(r))
}

func (h *StandaloneRedirect) getFallbackRedirect(r *http.Request) *url.URL {
	return MatchingPath(r)
}

var _ Redirect = &SSOServerRedirect{}

type SSOServerRedirect struct {
	fallbackRedirect *url.URL
	*cleaner
}

func NewSSOServerRedirect(config *config.Config) (*SSOServerRedirect, error) {
	u, err := url.Parse(config.SSO.ServerDefaultRedirectURL)
	if err != nil {
		return nil, fmt.Errorf("parsing fallback redirect URL: %w", err)
	}

	return &SSOServerRedirect{
		fallbackRedirect: u,
		cleaner:          newAbsoluteCleaner([]string{config.SSO.Domain}),
	}, nil
}

func (h *SSOServerRedirect) Canonical(r *http.Request) string {
	target := redirectQueryParam(r)
	redirect, err := url.Parse(target)
	if err != nil {
		redirect = fallback(r, target, h.fallbackRedirect)
	}

	return h.Clean(r, redirect.String())
}

func (h *SSOServerRedirect) Clean(r *http.Request, target string) string {
	return h.clean(r, target, h.fallbackRedirect)
}

var _ Redirect = &SSOProxyRedirect{}

type SSOProxyRedirect struct {
	fallbackRedirect *url.URL
	*cleaner
}

func NewSSOProxyRedirect(ingresses *ingress.Ingresses) *SSOProxyRedirect {
	return &SSOProxyRedirect{
		fallbackRedirect: ingresses.Single().NewURL(),
		cleaner:          newAbsoluteCleaner(ingresses.Hosts()),
	}
}

func (h *SSOProxyRedirect) Canonical(r *http.Request) string {
	// find matching request ingress, use as base redirect
	redirect, err := MatchingIngress(r)
	if err != nil {
		redirect = h.getFallbackRedirect()
	}

	// get redirect from request query parameter
	target := redirectQueryParam(r)
	redirectParamURL, err := url.Parse(target)
	if err != nil {
		logInvalidRedirect(r, target, redirect.String())
	} else {
		// preserve path, query and fragment from redirect parameter to base redirect
		redirect.Path = redirectParamURL.Path
		redirect.RawQuery = redirectParamURL.RawQuery
		redirect.Fragment = redirectParamURL.Fragment
	}

	return h.Clean(r, redirect.String())
}

func (h *SSOProxyRedirect) Clean(r *http.Request, target string) string {
	return h.clean(r, target, h.getFallbackRedirect())
}

// getFallbackRedirect returns a copy of the configured fallbackRedirect
func (h *SSOProxyRedirect) getFallbackRedirect() *url.URL {
	u := *h.fallbackRedirect
	return &u
}

type cleaner struct {
	Validator
}

func newAbsoluteCleaner(allowedHosts []string) *cleaner {
	return &cleaner{
		Validator: NewAbsoluteValidator(allowedHosts),
	}
}

func newRelativeCleaner(allowedHosts []string) *cleaner {
	return &cleaner{
		Validator: NewRelativeValidator(allowedHosts),
	}
}

func (c *cleaner) GetValidator() Validator {
	return c.Validator
}

func (c *cleaner) clean(r *http.Request, target string, fallbackTarget *url.URL) string {
	if c.IsValidRedirect(r, target) {
		return target
	}

	return fallback(r, target, fallbackTarget).String()
}

func redirectQueryParam(r *http.Request) string {
	return r.URL.Query().Get(RedirectQueryParameter)
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
