package request

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/paths"
)

var (
	InvalidLoginParameterError = errors.New("InvalidLoginParameter")
)

// CanonicalRedirectURL constructs a redirect URL that points back to the application.
func CanonicalRedirectURL(r *http.Request, ingress string) string {
	// 1. Default
	defaultPath := defaultRedirectURL(ingress)
	redirect := defaultPath

	// 2. Referer header is set
	referer := refererPath(r)
	if len(referer) > 0 {
		redirect = referer
	}

	// 3. Redirect parameter is set
	redirectParam, found := parseRedirectParam(r)
	if found {
		redirect = redirectParam
	}

	// 4. Ensure that empty path redirections falls back to the ingress' context path if applicable
	if len(redirect) == 0 {
		redirect = defaultPath
	}

	return redirect
}

func defaultRedirectURL(ingress string) string {
	defaultPath := "/"
	ingressPath := config.ParseIngress(ingress)

	if len(ingressPath) > 0 {
		defaultPath = ingressPath
	}

	return defaultPath
}

func parseRedirectParam(r *http.Request) (string, bool) {
	redirectParam := r.URL.Query().Get(RedirectURLParameter)
	if len(redirectParam) <= 0 {
		return "", false
	}

	redirectParamURL, err := url.Parse(redirectParam)
	if err != nil {
		return "", false
	}

	// strip scheme and host to avoid cross-domain redirects
	redirectParamURL.Scheme = ""
	redirectParamURL.Host = ""

	redirectParamURLString := redirectParamURL.String()

	if len(redirectParamURLString) == 0 {
		redirectParamURLString = "/"
	}

	return redirectParamURLString, true
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

func refererPath(r *http.Request) string {
	if len(r.Referer()) == 0 {
		return ""
	}

	referer, err := url.Parse(r.Referer())
	if err != nil {
		return ""
	}

	return referer.Path
}

// RetryURI returns a URI that should retry the desired route that failed.
// It only handles the routes exposed by Wonderwall, i.e. `/oauth2/*`. As these routes
// are related to the authentication flow, we default to redirecting back to the handled
// `/oauth2/login` endpoint unless the original request attempted to reach the logout-flow.
func RetryURI(r *http.Request, ingress string, loginCookie *openid.LoginCookie) string {
	retryURI := r.URL.Path
	prefix := config.ParseIngress(ingress)

	if strings.HasSuffix(retryURI, paths.OAuth2+paths.Logout) || strings.HasSuffix(retryURI, paths.OAuth2+paths.FrontChannelLogout) {
		return prefix + retryURI
	}

	redirect := CanonicalRedirectURL(r, ingress)

	if loginCookie != nil && len(loginCookie.Referer) > 0 {
		redirect = loginCookie.Referer
	}

	retryURI = fmt.Sprintf(prefix + paths.OAuth2 + paths.Login)
	retryURI = retryURI + fmt.Sprintf("?%s=%s", RedirectURLParameter, redirect)
	return retryURI
}
