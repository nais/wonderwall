package error_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	urlpkg "github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
)

func TestHandler_Error(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpHandler := idp.RelyingPartyHandler.GetErrorHandler()

	for _, test := range []struct {
		name               string
		expectedStatusCode int
		fn                 func(w http.ResponseWriter, r *http.Request, cause error)
	}{
		{
			name:               "bad request",
			expectedStatusCode: http.StatusBadRequest,
			fn:                 rpHandler.BadRequest,
		},
		{
			name:               "internal error",
			expectedStatusCode: http.StatusInternalServerError,
			fn:                 rpHandler.InternalError,
		},
		{
			name:               "unauthorized",
			expectedStatusCode: http.StatusUnauthorized,
			fn:                 rpHandler.Unauthorized,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := idp.GetRequest(idp.RelyingPartyServer.URL)
			w := httptest.NewRecorder()

			test.fn(w, r, fmt.Errorf("some error"))
			assert.Equal(t, test.expectedStatusCode, w.Result().StatusCode)
		})
	}
}

func TestHandler_Retry(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	handler := idp.RelyingPartyHandler.GetErrorHandler()

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
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:    "callback path",
			request: httpRequest("/oauth2/callback"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
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
			request: httpRequest("/domene/oauth2/login"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/domene"),
		},
		{
			name:    "logout with non-default ingress",
			request: httpRequest("/domene/oauth2/logout"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/logout",
		},
		{
			name:    "login with referer",
			request: httpRequest("/oauth2/login", "/api/me"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/api/me"),
		},
		{
			name:    "login with referer on non-default ingress",
			request: httpRequest("/domene/oauth2/login", "/api/me"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/api/me"),
		},
		{
			name:    "login with root referer",
			request: httpRequest("/oauth2/login", "/"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:    "login with root referer on non-default ingress",
			request: httpRequest("/domene/oauth2/login", "/"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:        "login with cookie referer",
			request:     httpRequest("/oauth2/login"),
			loginCookie: &openid.LoginCookie{Referer: "/"},
			want:        "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:        "login with empty cookie referer",
			request:     httpRequest("/oauth2/login"),
			loginCookie: &openid.LoginCookie{Referer: ""},
			want:        "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:        "login with cookie referer takes precedence over referer header",
			request:     httpRequest("/oauth2/login", "/api/me"),
			loginCookie: &openid.LoginCookie{Referer: "/api/headers"},
			want:        "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/api/headers"),
		},
		{
			name:        "login with cookie referer on non-default ingress",
			request:     httpRequest("/domene/oauth2/login"),
			loginCookie: &openid.LoginCookie{Referer: "/domene/api/me"},
			ingress:     "https://test.nav.no/domene",
			want:        "/domene/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/domene/api/me"),
		},
		{
			name:    "login with redirect parameter set",
			request: httpRequest("/oauth2/login?redirect=/api/me"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/api/me"),
		},
		{
			name:    "login with redirect parameter set and query parameters",
			request: httpRequest("/oauth2/login?redirect=/api/me?a=b%26c=d"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/api/me?a=b&c=d"),
		},
		{
			name:    "login with redirect parameter set on non-default ingress",
			request: httpRequest("/domene/oauth2/login?redirect=/api/me"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/api/me"),
		},
		{
			name:    "login with redirect parameter set takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=/other", "/api/me"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/other"),
		},
		{
			name:    "login with redirect parameter set to relative root takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=/", "/api/me"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:    "login with redirect parameter set to relative root on non-default ingress takes precedence over referer header",
			request: httpRequest("/domene/oauth2/login?redirect=/", "/api/me"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:    "login with redirect parameter set to absolute url takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=http://localhost:8080", "/api/me"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:    "login with redirect parameter set to absolute url with trailing slash takes precedence over referer header",
			request: httpRequest("/oauth2/login?redirect=http://localhost:8080/", "/api/me"),
			want:    "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:    "login with redirect parameter set to absolute url on non-default ingress takes precedence over referer header",
			request: httpRequest("/domene/oauth2/login?redirect=http://localhost:8080/", "/api/me"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/"),
		},
		{
			name:        "login with cookie referer takes precedence over redirect parameter",
			request:     httpRequest("/oauth2/login?redirect=/other"),
			loginCookie: &openid.LoginCookie{Referer: "/domene/api/me"},
			want:        "/oauth2/login?redirect-encoded=" + urlpkg.RedirectEncoded("/domene/api/me"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if len(test.ingress) == 0 {
				test.ingress = mock.Ingress
			}

			idp.SetIngresses(test.ingress)

			ing, err := ingress.ParseIngress(test.ingress)
			assert.NoError(t, err)

			test.request = mw.RequestWithPath(test.request, ing.Path())

			retryURI := handler.Retry(test.request, test.loginCookie)
			assert.Equal(t, test.want, retryURI)
		})
	}
}
