package request_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/request"
)

func TestCanonicalRedirectURL(t *testing.T) {
	r, err := http.NewRequest("GET", "http://localhost:8080/oauth2/login", nil)
	assert.NoError(t, err)

	// Default URL is /
	assert.Equal(t, "/", request.CanonicalRedirectURL(r))

	// HTTP Referer header is 2nd priority
	r.Header.Set("referer", "http://localhost:8080/foo/bar/baz?gnu=notunix")
	assert.Equal(t, "/foo/bar/baz", request.CanonicalRedirectURL(r))

	// If redirect parameter is set, use that
	v := &url.Values{}
	v.Set("redirect", "https://google.com/path/to/redirect?val1=foo&val2=bar")
	r.URL.RawQuery = v.Encode()
	assert.Equal(t, "/path/to/redirect?val1=foo&val2=bar", request.CanonicalRedirectURL(r))
}

func TestLoginURLParameter(t *testing.T) {
	for _, test := range []struct {
		name      string
		parameter string
		fallback  string
		supported openid.Supported
		url       string
		expectErr error
		expected  string
	}{
		{
			name:     "no URL parameter should use fallback value",
			url:      "http://localhost:8080/oauth2/login",
			expected: "valid",
		},
		{
			name:     "non-matching URL parameter should be ignored",
			url:      "http://localhost:8080/oauth2/login?other_param=value2",
			expected: "valid",
		},
		{
			name:     "matching URL parameter should take precedence",
			url:      "http://localhost:8080/oauth2/login?param=valid2",
			expected: "valid2",
		},
		{
			name:      "invalid URL parameter value should return error",
			url:       "http://localhost:8080/oauth2/login?param=invalid",
			expectErr: request.InvalidLoginParameterError,
		},
		{
			name:      "invalid fallback value should return error",
			fallback:  "invalid",
			url:       "http://localhost:8080/oauth2/login",
			expectErr: request.InvalidLoginParameterError,
		},
		{
			name:      "no supported values should return error",
			url:       "http://localhost:8080/oauth2/login",
			supported: openid.Supported{""},
			expectErr: request.InvalidLoginParameterError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", test.url, nil)
			assert.NoError(t, err)

			// default test values
			parameter := "param"
			fallback := "valid"
			supported := openid.Supported{"valid", "valid2"}

			if len(test.parameter) > 0 {
				parameter = test.parameter
			}

			if len(test.fallback) > 0 {
				fallback = test.fallback
			}

			if len(test.supported) > 0 {
				supported = test.supported
			}

			val, err := request.LoginURLParameter(r, parameter, fallback, supported)

			if test.expectErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, val)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestRetryURI(t *testing.T) {
	httpRequest := func(url string, referer ...string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
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

			retryURI := request.RetryURI(test.request, test.ingress, test.loginCookie)
			assert.Equal(t, test.want, retryURI)
		})
	}
}
