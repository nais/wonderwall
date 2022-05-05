package router_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

func TestHandler_GetSessionFallback(t *testing.T) {
	p := mock.NewTestProvider()
	h := newHandler(p)
	tokens := makeTokens(p)

	t.Run("request without fallback session cookies", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, err := h.GetSessionFallback(r)
		assert.Error(t, err)
	})

	t.Run("request with fallback session cookies", func(t *testing.T) {
		r := makeRequestWithFallbackCookies(t, h, tokens)
		sessionData, err := h.GetSessionFallback(r)
		assert.NoError(t, err)
		assert.Equal(t, "sid", sessionData.ExternalSessionID)
		assert.Equal(t, tokens.AccessToken.GetSerialized(), sessionData.AccessToken)
		assert.Equal(t, tokens.IDToken.GetSerialized(), sessionData.IDToken)
		assert.Equal(t, "id-token-jti", sessionData.Claims.IDTokenJti)
		assert.Equal(t, "access-token-jti", sessionData.Claims.AccessTokenJti)
	})
}

func TestHandler_SetSessionFallback(t *testing.T) {
	provider := mock.NewTestProvider()
	h := newHandler(provider)

	// request should set session cookies in response
	writer := httptest.NewRecorder()
	expiresIn := time.Minute
	tokens := makeTokens(provider)
	data := session.NewData("sid", tokens)
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
			want:       tokens.IDToken.GetSerialized(),
		},
		{
			cookieName: h.SessionFallbackAccessTokenCookieName(),
			want:       tokens.AccessToken.GetSerialized(),
		},
	} {
		assertCookieExists(t, h, test.cookieName, test.want, cookies)
	}
}

func TestHandler_DeleteSessionFallback(t *testing.T) {
	p := mock.NewTestProvider()
	h := newHandler(p)
	tokens := makeTokens(p)

	t.Run("expire cookies if they are set", func(t *testing.T) {
		r := makeRequestWithFallbackCookies(t, h, tokens)
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

func makeRequestWithFallbackCookies(t *testing.T, h *router.Handler, tokens *jwt.Tokens) *http.Request {
	writer := httptest.NewRecorder()
	expiresIn := time.Minute
	data := session.NewData("sid", tokens)
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

func makeTokens(provider mock.TestProvider) *jwt.Tokens {
	jwks := *provider.PrivateJwkSet()
	jwksPublic, err := provider.GetPublicJwkSet(context.TODO())
	if err != nil {
		log.Fatalf("getting public jwk set: %+v", err)
	}

	signer, ok := jwks.Key(0)
	if !ok {
		log.Fatalf("getting signer")
	}

	idToken := jwtlib.New()
	idToken.Set("jti", "id-token-jti")

	signedIdToken, err := jwtlib.Sign(idToken, jwtlib.WithKey(jwa.RS256, signer))
	if err != nil {
		log.Fatalf("signing id_token: %+v", err)
	}

	parsedIdToken, err := jwtlib.Parse(signedIdToken, jwtlib.WithKeySet(*jwksPublic))
	if err != nil {
		log.Fatalf("parsing signed id_token: %+v", err)
	}

	accessToken := jwtlib.New()
	accessToken.Set("jti", "access-token-jti")

	signedAccessToken, err := jwtlib.Sign(accessToken, jwtlib.WithKey(jwa.RS256, signer))
	if err != nil {
		log.Fatalf("signing access_token: %+v", err)
	}
	parsedAccessToken, err := jwtlib.Parse(signedAccessToken, jwtlib.WithKeySet(*jwksPublic))
	if err != nil {
		log.Fatalf("parsing signed access_token: %+v", err)
	}

	return &jwt.Tokens{
		IDToken:     jwt.NewIDToken(string(signedIdToken), parsedIdToken),
		AccessToken: jwt.NewAccessToken(string(signedAccessToken), parsedAccessToken),
	}
}
