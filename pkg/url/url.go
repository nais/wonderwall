package url

import (
	"errors"
	"net/http"
	"net/url"

	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/router/paths"
)

const (
	RedirectQueryParameter = "redirect"
)

var (
	ErrNoMatchingIngress = errors.New("request host does not match any configured ingresses")
)

// Login constructs a URL string that points to the login path for the given target URL.
// The given redirect string should point to the location to be redirected to after login.
func Login(target *url.URL, redirect string) string {
	u := target.JoinPath(paths.OAuth2, paths.Login)

	v := u.Query()
	v.Set(RedirectQueryParameter, redirect)
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

func LoginCallback(r *http.Request) (string, error) {
	return makeCallbackURL(r, paths.LoginCallback)
}

func LogoutCallback(r *http.Request) (string, error) {
	return makeCallbackURL(r, paths.LogoutCallback)
}

func makeCallbackURL(r *http.Request, callbackPath string) (string, error) {
	u, err := MatchingIngress(r)
	if err != nil {
		return "", err
	}

	return u.JoinPath(paths.OAuth2, callbackPath).String(), nil
}

func MatchingPath(r *http.Request) *url.URL {
	u := &url.URL{}

	p, found := mw.PathFrom(r.Context())
	if found && len(p) > 0 {
		u.Path = p
	} else {
		u.Path = "/"
	}

	return u
}

func MatchingIngress(r *http.Request) (*url.URL, error) {
	ing, found := mw.IngressFrom(r.Context())
	if !found {
		return nil, ErrNoMatchingIngress
	}

	return ing.NewURL(), nil
}
