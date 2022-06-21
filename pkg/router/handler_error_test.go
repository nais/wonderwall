package router_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router"
)

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

			retryURI := router.RetryURI(test.request, test.ingress, test.loginCookie)
			assert.Equal(t, test.want, retryURI)
		})
	}
}
