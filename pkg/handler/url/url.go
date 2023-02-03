package url

import (
	"fmt"
	"net/http"
	"net/url"

	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/router/paths"
)

const (
	RedirectURLParameter = "redirect"
)

// CanonicalRedirect constructs a redirect URL that points back to the application.
func CanonicalRedirect(r *http.Request) string {
	ingressPath, ok := mw.PathFrom(r.Context())
	if len(ingressPath) == 0 || !ok {
		ingressPath = "/"
	}

	// 1. Default
	redirect := ingressPath

	// 2. Redirect parameter is set
	redirectParam := r.URL.Query().Get(RedirectURLParameter)
	if len(redirectParam) > 0 {
		redirect = redirectParam
	}

	// Ensure URL isn't encoded
	redirect, err := url.QueryUnescape(redirect)
	if err != nil {
		return ingressPath
	}

	parsed, err := url.ParseRequestURI(redirect)
	if err != nil {
		// Silently fall back to ingress path
		return ingressPath
	}

	// Strip scheme and host to avoid cross-domain redirects
	parsed.Scheme = ""
	parsed.Host = ""

	redirect = parsed.String()

	// Root path without trailing slash is empty
	if len(parsed.Path) == 0 {
		redirect = "/"
	}

	// Ensure that empty path redirections falls back to the ingress' context path if applicable
	if len(redirect) == 0 {
		redirect = ingressPath
	}

	return redirect
}

// Login constructs a URL string that points to the login path for the given target URL.
// The given redirect string should point to the location to be redirected to after login.
func Login(target *url.URL, redirect string) string {
	u := target.JoinPath(paths.OAuth2, paths.Login)

	v := u.Query()
	v.Set(RedirectURLParameter, redirect)
	u.RawQuery = v.Encode()

	return u.String()
}

// LoginRelative constructs the relative URL with an absolute path that points to the application's login path, given an optional path prefix.
// The given redirect string should point to the location to be redirected to after login.
func LoginRelative(prefix, redirect string) string {
	u := new(url.URL)
	u.Path = prefix

	if prefix == "" {
		u.Path = "/"
	}

	return Login(u, redirect)
}

func LoginCallbackURL(r *http.Request) (string, error) {
	return makeCallbackURL(r, paths.LoginCallback)
}

func LogoutCallbackURL(r *http.Request) (string, error) {
	return makeCallbackURL(r, paths.LogoutCallback)
}

func makeCallbackURL(r *http.Request, callbackPath string) (string, error) {
	u, err := Ingress(r)
	if err != nil {
		return "", err
	}

	return u.JoinPath(paths.OAuth2, callbackPath).String(), nil
}

func Ingress(r *http.Request) (*url.URL, error) {
	ing, found := mw.IngressFrom(r.Context())
	if !found {
		return nil, fmt.Errorf("request host does not match any configured ingresses")
	}

	return ing.NewURL(), nil
}
