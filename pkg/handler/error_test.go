package handler_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
)

func TestHandler_Error(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpHandler := idp.RelyingPartyHandler

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
	get := func(url string) *http.Request {
		return httptest.NewRequest(http.MethodGet, url, nil)
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
			request: get("/oauth2/login"),
			want:    "/oauth2/login",
		},
		{
			name:    "callback path",
			request: get("/oauth2/callback"),
			want:    "/oauth2/login?redirect=%2F",
		},
		{
			name:    "logout path",
			request: get("/oauth2/logout"),
			want:    "/oauth2/logout",
		},
		{
			name:    "local logout path",
			request: get("/oauth2/logout/local"),
			want:    "/oauth2/logout/local",
		},
		{
			name:    "logout callback path",
			request: get("/oauth2/logout/callback"),
			want:    "/oauth2/logout",
		},
		{
			name:    "front-channel logout path",
			request: get("/oauth2/logout/frontchannel"),
			want:    "/oauth2/logout/frontchannel",
		},
		{
			name:    "login with non-default ingress",
			request: get("/domene/oauth2/login"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login",
		},
		{
			name:    "logout with non-default ingress",
			request: get("/domene/oauth2/logout"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/logout",
		},
		{
			name:    "login with query parameters",
			request: get("/oauth2/login?acr=Level3&locale=en"),
			want:    "/oauth2/login?acr=Level3&locale=en",
		},
		{
			name:    "login with redirect parameter set",
			request: get("/oauth2/login?redirect=%2Fapi%2Fme"),
			want:    "/oauth2/login?redirect=%2Fapi%2Fme",
		},
		{
			name:    "login with redirect parameter set and query parameters",
			request: get("/oauth2/login?redirect=%2Fapi%2Fme%3Fa%3Db%26c%3Dd"),
			want:    "/oauth2/login?redirect=%2Fapi%2Fme%3Fa%3Db%26c%3Dd",
		},
		{
			name:    "login with redirect parameter set on non-default ingress",
			request: get("/domene/oauth2/login?redirect=%2Fapi%2Fme"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect=%2Fapi%2Fme",
		},
		{
			name:        "callback with cookie referer",
			request:     get("/oauth2/callback"),
			loginCookie: &openid.LoginCookie{Referer: "/"},
			want:        "/oauth2/login?redirect=%2F",
		},
		{
			name:        "callback with empty cookie referer",
			request:     get("/oauth2/callback"),
			loginCookie: &openid.LoginCookie{Referer: ""},
			want:        "/oauth2/login?redirect=%2F",
		},
		{
			name:        "callback with cookie referer on non-default ingress",
			request:     get("/domene/oauth2/callback"),
			loginCookie: &openid.LoginCookie{Referer: "/domene/api/me"},
			ingress:     "https://test.nav.no/domene",
			want:        "/domene/oauth2/login?redirect=%2Fdomene%2Fapi%2Fme",
		},
		{
			name:    "callback with query parameters",
			request: get("/oauth2/callback?code=some-code&state=some-state"),
			want:    "/oauth2/login?redirect=%2F",
		},
		{
			name:    "callback with redirect parameter on non-default ingress",
			request: get("/domene/oauth2/callback"),
			ingress: "https://test.nav.no/domene",
			want:    "/domene/oauth2/login?redirect=%2Fdomene",
		},
		{
			name:        "callback with cookie referer takes precedence over redirect parameter",
			request:     get("/oauth2/callback?redirect=/other"),
			loginCookie: &openid.LoginCookie{Referer: "/domene/api/me"},
			want:        "/oauth2/login?redirect=%2Fdomene%2Fapi%2Fme",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if len(test.ingress) == 0 {
				test.ingress = mock.Ingress
			}

			cfg := mock.Config()
			cfg.Ingresses = []string{test.ingress}
			idp := mock.NewIdentityProvider(cfg)
			defer idp.Close()

			ing, err := ingress.ParseIngress(test.ingress)
			assert.NoError(t, err)

			test.request = mw.RequestWithPath(test.request, ing.Path())

			retryURI := idp.RelyingPartyHandler.Retry(test.request, test.loginCookie)
			assert.Equal(t, test.want, retryURI)
		})
	}
}
