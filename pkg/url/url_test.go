package url_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/openid"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

func TestCanonicalRedirect(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost:8080/oauth2/login", nil)

	t.Run("default redirect", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			ingress  string
			expected string
		}{
			{
				name:     "root with trailing slash",
				ingress:  "http://localhost:8080/",
				expected: "/",
			},
			{
				name:     "root without trailing slash",
				ingress:  "http://localhost:8080",
				expected: "/",
			},
			{
				name:     "path with trailing slash",
				ingress:  "http://localhost:8080/path/",
				expected: "/path",
			},
			{
				name:     "path without trailing slash",
				ingress:  "http://localhost:8080/path",
				expected: "/path",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				assert.Equal(t, test.expected, urlpkg.CanonicalRedirect(r, test.ingress))
			})
		}
	})

	// Default path is /some-path
	ingress := "http://localhost:8080/some-path"

	// HTTP Referer header is 2nd priority
	t.Run("Referer header is set", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			value    string
			expected string
		}{
			{
				name:     "full URL",
				value:    "http://localhost:8080/foo/bar/baz",
				expected: "/foo/bar/baz",
			},
			{
				name:     "full URL with query parameters",
				value:    "http://localhost:8080/foo/bar/baz?gnu=notunix",
				expected: "/foo/bar/baz?gnu=notunix",
			},
			{
				name:     "absolute path",
				value:    "/foo/bar/baz",
				expected: "/foo/bar/baz",
			},
			{
				name:     "absolute path with query parameters",
				value:    "/foo/bar/baz?gnu=notunix",
				expected: "/foo/bar/baz?gnu=notunix",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				r.Header.Set("Referer", test.value)
				assert.Equal(t, test.expected, urlpkg.CanonicalRedirect(r, ingress))
			})
		}
	})

	// If redirect parameter is set, use that
	t.Run("redirect parameter is set", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			value    string
			expected string
		}{
			{
				name:     "complete url with parameters",
				value:    "http://localhost:8080/path/to/redirect?val1=foo&val2=bar",
				expected: "/path/to/redirect?val1=foo&val2=bar",
			},
			{
				name:     "root url with trailing slash",
				value:    "http://localhost:8080/",
				expected: "/",
			},
			{
				name:     "root url without trailing slash",
				value:    "http://localhost:8080",
				expected: "/",
			},
			{
				name:     "url path with trailing slash",
				value:    "http://localhost:8080/path/",
				expected: "/path/",
			},
			{
				name:     "url path without trailing slash",
				value:    "http://localhost:8080/path",
				expected: "/path",
			},
			{
				name:     "absolute path",
				value:    "/path",
				expected: "/path",
			},
			{
				name:     "absolute path with query parameters",
				value:    "/path?gnu=notunix",
				expected: "/path?gnu=notunix",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				v := &url.Values{}
				v.Set("redirect", test.value)
				r.URL.RawQuery = v.Encode()
				assert.Equal(t, test.expected, urlpkg.CanonicalRedirect(r, ingress))
			})
		}
	})
}

func TestRetry(t *testing.T) {
	httpRequest := func(url string, referer ...string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		if len(referer) > 0 {
			req.Header.Add("Referer", referer[0])
		}
		return req
	}

	for _, test := range []struct {
		name        string
		request     *http.Request
		ingress     string
		loginCookie *openid.LoginCookie
		want        string
	}{
		{
			name:    "login path",
			request: httpRequest("/oauth2/login"),
			want:    "/oauth2/login?redirect=/",
		},
		{
			name:    "callback path",
			request: httpRequest("/oauth2/callback"),
			want:    "/oauth2/login?redirect=/",
		},
		{
			name:    "logout path",
			request: httpRequest("/oauth2/logout"),
			want:    "/oauth2/logout",
		},
		{
			name:    "front-channel logout path",
			request: httpRequest("/oauth2/logout/frontchannel"),
			want:    "/oauth2/logout/frontchannel",
		},
		{
			name:    "login with non-default ingress",
			request: httpRequest("/oauth2/login"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect=/domene",
		},
		{
			name:    "logout with non-default ingress",
			request: httpRequest("/oauth2/logout"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/logout",
		},
		{
			name:    "login with referer",
			request: httpRequest("/oauth2/login", "/api/me"),
			want:    "/oauth2/login?redirect=/api/me",
		},
		{
			name:    "login with referer on non-default ingress",
			request: httpRequest("/oauth2/login", "/api/me"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect=/api/me",
		},
		{
			name:    "login with root referer",
			request: httpRequest("/oauth2/login", "/"),
			want:    "/oauth2/login?redirect=/",
		},
		{
			name:    "login with root referer on non-default ingress",
			request: httpRequest("/oauth2/login", "/"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect=/",
		},
		{
			name:        "login with cookie referer",
			request:     httpRequest("/oauth2/login"),
			loginCookie: &openid.LoginCookie{Referer: "/"},
			want:        "/oauth2/login?redirect=/",
		},
		{
			name:        "login with empty cookie referer",
			request:     httpRequest("/oauth2/login"),
			loginCookie: &openid.LoginCookie{Referer: ""},
			want:        "/oauth2/login?redirect=/",
		},
		{
			name:        "login with cookie referer takes precedence over referer header",
			request:     httpRequest("/oauth2/login", "/api/me"),
			loginCookie: &openid.LoginCookie{Referer: "/api/headers"},
			want:        "/oauth2/login?redirect=/api/headers",
		},
		{
			name:        "login with cookie referer on non-default ingress",
			request:     httpRequest("/oauth2/login"),
			loginCookie: &openid.LoginCookie{Referer: "/domene/api/me"},
			ingress:     "https://test.nav.no/domene",
			want:        "/domene/oauth2/login?redirect=/domene/api/me",
		},
		{
			name:    "login with redirect parameter set",
			request: httpRequest("/oauth2/login?redirect=/api/me"),
			want:    "/oauth2/login?redirect=/api/me",
		},
		{
			name:    "login with redirect parameter set and query parameters",
			request: httpRequest("/oauth2/login?redirect=/api/me?a=b%26c=d"),
			want:    "/oauth2/login?redirect=/api/me?a=b&c=d",
		},
		{
			name:    "login with redirect parameter set on non-default ingress",
			request: httpRequest("/oauth2/login?redirect=/api/me"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect=/api/me",
		},
		{
			name:    "login with redirect parameter set takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=/other", "/api/me"),
			want:    "/oauth2/login?redirect=/other",
		},
		{
			name:    "login with redirect parameter set to relative root takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=/", "/api/me"),
			want:    "/oauth2/login?redirect=/",
		},
		{
			name:    "login with redirect parameter set to relative root on non-default ingress takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=/", "/api/me"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect=/",
		},
		{
			name:    "login with redirect parameter set to absolute url takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=http://localhost:8080", "/api/me"),
			want:    "/oauth2/login?redirect=/",
		},
		{
			name:    "login with redirect parameter set to absolute url with trailing slash takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=http://localhost:8080/", "/api/me"),
			want:    "/oauth2/login?redirect=/",
		},
		{
			name:    "login with redirect parameter set to absolute url on non-default ingress takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=http://localhost:8080/", "/api/me"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect=/",
		},
		{
			name:        "login with cookie referer takes precedence over redirect parameter",
			request:     httpRequest("/oauth2/login?redirect=/other"),
			loginCookie: &openid.LoginCookie{Referer: "/domene/api/me"},
			want:        "/oauth2/login?redirect=/domene/api/me",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if len(test.ingress) == 0 {
				test.ingress = "/"
			}

			retryURI := urlpkg.Retry(test.request, test.ingress, test.loginCookie)
			assert.Equal(t, test.want, retryURI)
		})
	}
}

func TestLoginURL(t *testing.T) {
	for _, test := range []struct {
		name           string
		prefix         string
		redirectTarget string
		want           string
	}{
		{
			name:           "no prefix",
			prefix:         "",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/oauth2/login?redirect=https://test.example.com?some=param&other=param2",
		},
		{
			name:           "with prefix",
			prefix:         "/path",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/path/oauth2/login?redirect=https://test.example.com?some=param&other=param2",
		},
		{
			name:           "we need to go deeper",
			prefix:         "/deeper/path",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/deeper/path/oauth2/login?redirect=https://test.example.com?some=param&other=param2",
		},
		{
			name:           "relative target",
			prefix:         "",
			redirectTarget: "/path?some=param&other=param2",
			want:           "/oauth2/login?redirect=/path?some=param&other=param2",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			loginUrl := urlpkg.LoginURL(test.prefix, test.redirectTarget)
			assert.Equal(t, test.want, loginUrl)
		})
	}
}
