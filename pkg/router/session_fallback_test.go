package router_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

func TestHandler_GetSessionFallback(t *testing.T) {
	h := newHandler(mock.NewTestProvider())

	t.Run("request without fallback session cookies", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, err := h.GetSessionFallback(r)
		assert.Error(t, err)
	})

	t.Run("request with fallback session cookies", func(t *testing.T) {
		r := makeRequestWithFallbackCookies(t)
		sessionData, err := h.GetSessionFallback(r)
		assert.NoError(t, err)
		assert.Equal(t, "sid", sessionData.ExternalSessionID)
		assert.Equal(t, "access_token", sessionData.AccessToken)
		assert.Equal(t, "id_token", sessionData.IDToken)
	})
}

func TestHandler_SetSessionFallback(t *testing.T) {
	h := newHandler(mock.NewTestProvider())

	// request should set session cookies in response
	writer := httptest.NewRecorder()
	expiresIn := time.Minute
	data := session.NewData("sid", "access_token", "id_token")
	err := h.SetSessionFallback(writer, data, expiresIn)
	assert.NoError(t, err)

	cookies := writer.Result().Cookies()

	for _, test := range []struct {
		cookieName string
		want       string
	}{
		{
			cookieName: h.SessionFallbackExternalIDCookieName(),
			want:       "sid",
		},
		{
			cookieName: h.SessionFallbackIDTokenCookieName(),
			want:       "id_token",
		},
		{
			cookieName: h.SessionFallbackAccessTokenCookieName(),
			want:       "access_token",
		},
	} {
		assertCookieExists(t, h, test.cookieName, test.want, cookies)
	}
}

func TestHandler_DeleteSessionFallback(t *testing.T) {
	h := newHandler(mock.NewTestProvider())

	t.Run("expire cookies if they are set", func(t *testing.T) {
		r := makeRequestWithFallbackCookies(t)
		writer := httptest.NewRecorder()
		h.DeleteSessionFallback(writer, r)
		cookies := writer.Result().Cookies()

		assert.NotEmpty(t, cookies)
		assert.Len(t, cookies, 3)

		assertCookieExpired(t, h.SessionFallbackExternalIDCookieName(), cookies)
		assertCookieExpired(t, h.SessionFallbackIDTokenCookieName(), cookies)
		assertCookieExpired(t, h.SessionFallbackAccessTokenCookieName(), cookies)
	})

	t.Run("skip expiring cookies if they are not set", func(t *testing.T) {
		writer := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		h.DeleteSessionFallback(writer, r)
		cookies := writer.Result().Cookies()

		assert.Empty(t, cookies)
	})
}

func makeRequestWithFallbackCookies(t *testing.T) *http.Request {
	h := newHandler(mock.NewTestProvider())
	writer := httptest.NewRecorder()
	expiresIn := time.Minute
	data := session.NewData("sid", "access_token", "id_token")
	err := h.SetSessionFallback(writer, data, expiresIn)
	assert.NoError(t, err)

	cookies := writer.Result().Cookies()

	externalSessionIDCookie := getCookieFromJar(h.SessionFallbackExternalIDCookieName(), cookies)
	assert.NotNil(t, externalSessionIDCookie)
	idTokenCookie := getCookieFromJar(h.SessionFallbackIDTokenCookieName(), cookies)
	assert.NotNil(t, idTokenCookie)
	accessTokenCookie := getCookieFromJar(h.SessionFallbackAccessTokenCookieName(), cookies)
	assert.NotNil(t, accessTokenCookie)

	// make request with fallback session cookies set
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(externalSessionIDCookie)
	r.AddCookie(idTokenCookie)
	r.AddCookie(accessTokenCookie)

	return r
}

func assertCookieExpired(t *testing.T, cookieName string, cookies []*http.Cookie) {
	expired := getCookieFromJar(cookieName, cookies)
	assert.NotNil(t, expired)
	assert.Less(t, expired.MaxAge, 0)
	assert.True(t, expired.Expires.Before(time.Now()))
	assert.Empty(t, expired.Value)
}

func assertCookieExists(t *testing.T, h *router.Handler, cookieName, expectedValue string, cookies []*http.Cookie) {
	desiredCookie := getCookieFromJar(cookieName, cookies)
	assert.NotNil(t, desiredCookie)

	ciphertext, err := base64.StdEncoding.DecodeString(desiredCookie.Value)
	assert.NoError(t, err)

	plainbytes, err := h.Crypter.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, expectedValue, string(plainbytes))
}
