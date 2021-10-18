package request

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/openid"
)

var (
	InvalidLoginParameterError = errors.New("InvalidLoginParameter")
)

// CanonicalRedirectURL constructs a redirect URL that points back to the application.
func CanonicalRedirectURL(r *http.Request) string {
	redirectURL := "/"

	referer := RefererPath(r)
	if len(referer) > 0 {
		redirectURL = referer
	}

	override := r.URL.Query().Get(RedirectURLParameter)
	if len(override) > 0 {
		referer, err := url.Parse(override)
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
func LoginURLParameter(r *http.Request, parameter, fallback string, supported openid.Supported) (string, error) {
	value := r.URL.Query().Get(parameter)

	if len(value) == 0 {
		value = fallback
	}

	if supported.Contains(value) {
		return value, nil
	}

	return value, fmt.Errorf("%w: invalid value for %s=%s", InvalidLoginParameterError, parameter, value)
}

func PostLogoutRedirectURI(r *http.Request, fallback string) string {
	value := r.URL.Query().Get(PostLogoutRedirectURIParameter)

	if len(value) > 0 {
		return value
	}
	return fallback
}

func RefererPath(r *http.Request) string {
	result := ""

	referer, err := url.Parse(r.Referer())
	if err == nil && len(referer.Path) > 0 {
		result = referer.Path
	}

	return result
}

// RetryURI returns a URI that should retry the desired route that failed.
// It only handles the routes exposed by Wonderwall, i.e. `/oauth2/*`. As these routes
// are related to the authentication flow, we default to redirecting back to the handled
// `/oauth2/login` endpoint unless the original request attempted to reach the logout-flow.
func RetryURI(r *http.Request, ingress string, loginCookie *cookie.Login) string {
	retryURI := r.URL.Path

	prefix := config.ParseIngress(ingress)

	if strings.HasSuffix(retryURI, "/oauth2/logout") || strings.HasSuffix(retryURI, "/oauth2/logout/frontchannel") {
		return prefix + retryURI
	}

	// 1. Default
	redirect := "/"

	// 2. Ingress has path prefix
	if len(prefix) > 0 {
		redirect = prefix
	}

	// 3. Referer header is set
	referer := RefererPath(r)
	if len(referer) > 0 {
		redirect = referer
	}

	// 4. Redirect parameter is set
	redirectURLFromParam, err := url.Parse(r.URL.Query().Get(RedirectURLParameter))
	if err == nil && len(redirectURLFromParam.Path) > 0 {
		redirect = redirectURLFromParam.Path
	}

	// 5. Login cookie exists and referer is set
	if loginCookie != nil && len(loginCookie.Referer) > 0 {
		redirect = loginCookie.Referer
	}

	retryURI = fmt.Sprintf("%s/oauth2/login", prefix)
	retryURI = retryURI + fmt.Sprintf("?%s=%s", RedirectURLParameter, redirect)
	return retryURI
}
