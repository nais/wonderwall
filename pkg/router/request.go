package router

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/nais/wonderwall/pkg/config"
)

var (
	InvalidLoginParameterError = errors.New("InvalidLoginParameter")
)

// CanonicalRedirectURL constructs a redirect URL that points back to the application.
func CanonicalRedirectURL(r *http.Request) string {
	redirectURL := "/"
	referer, err := url.Parse(r.Referer())
	if err == nil && len(referer.Path) > 0 {
		redirectURL = referer.Path
	}
	override := r.URL.Query().Get(RedirectURLParameter)
	if len(override) > 0 {
		referer, err = url.Parse(override)
		if err == nil {
			// strip scheme and host to avoid cross-domain redirects
			referer.Scheme = ""
			referer.Host = ""
			redirectURL = referer.String()
		}
	}
	return redirectURL
}

// LoginURLParameter attempts to get a given parameter from the given HTTP request, falling back if none found.
// The value must exist in the supplied list of supported values.
func LoginURLParameter(r *http.Request, parameter, fallback string, supported config.Supported) (string, error) {
	value := r.URL.Query().Get(parameter)

	if len(value) == 0 {
		value = fallback
	}

	if supported.Contains(value) {
		return value, nil
	}

	return value, fmt.Errorf("%w: invalid value for %s=%s", InvalidLoginParameterError, parameter, value)
}
