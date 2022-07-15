package url

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/paths"
)

const (
	RedirectURLParameter = "redirect"
)

// CanonicalRedirect constructs a redirect URL that points back to the application.
func CanonicalRedirect(r *http.Request, ingress string) string {
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

// Retry returns a URI that should retry the desired route that failed.
// It only handles the routes exposed by Wonderwall, i.e. `/oauth2/*`. As these routes
// are related to the authentication flow, we default to redirecting back to the handled
// `/oauth2/login` endpoint unless the original request attempted to reach the logout-flow.
func Retry(r *http.Request, ingress string, loginCookie *openid.LoginCookie) string {
	retryURI := r.URL.Path
	prefix := config.ParseIngress(ingress)

	if strings.HasSuffix(retryURI, paths.OAuth2+paths.Logout) || strings.HasSuffix(retryURI, paths.OAuth2+paths.FrontChannelLogout) {
		return prefix + retryURI
	}

	redirect := CanonicalRedirect(r, ingress)

	if loginCookie != nil && len(loginCookie.Referer) > 0 {
		redirect = loginCookie.Referer
	}

	retryURI = fmt.Sprintf(prefix + paths.OAuth2 + paths.Login)
	retryURI = retryURI + fmt.Sprintf("?%s=%s", RedirectURLParameter, redirect)
	return retryURI
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

	// root path without trailing slash is empty
	if len(redirectParamURLString) == 0 {
		redirectParamURLString = "/"
	}

	return redirectParamURLString, true
}

func refererPath(r *http.Request) string {
	if len(r.Referer()) == 0 {
		return ""
	}

	referer, err := url.Parse(r.Referer())
	if err != nil {
		return ""
	}

	// strip scheme and host to avoid cross-domain redirects
	referer.Scheme = ""
	referer.Host = ""
	return referer.String()
}
