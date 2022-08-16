package handler_test

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

	"github.com/nais/wonderwall/pkg/handler"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
)

func TestHandler_GetSessionFallback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	tokens := makeTokens(idp.Provider)
	rpHandler := idp.RelyingPartyHandler

	t.Run("request without fallback session cookies", func(t *testing.T) {
		r := idp.GetRequest("/")
		w := httptest.NewRecorder()
		_, err := rpHandler.GetSessionFallback(w, r)
		assert.Error(t, err)
	})

	t.Run("request with fallback session cookies", func(t *testing.T) {
		r := makeRequestWithFallbackCookies(t, idp, tokens)
		w := httptest.NewRecorder()
		sessionData, err := rpHandler.GetSessionFallback(w, r)
		assert.NoError(t, err)
		assert.Equal(t, "sid", sessionData.ExternalSessionID)
		assert.Equal(t, tokens.AccessToken, sessionData.AccessToken)
		assert.Equal(t, tokens.IDToken.GetSerialized(), sessionData.IDToken)
		assert.Equal(t, "id-token-jti", sessionData.IDTokenJwtID)
		assert.Empty(t, sessionData.RefreshToken)
	})
}

func TestHandler_SetSessionFallback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	tokens := makeTokens(idp.Provider)
	rpHandler := idp.RelyingPartyHandler

	// request should set session cookies in response
	writer := httptest.NewRecorder()
	r := idp.GetRequest("/")
	expiresIn := time.Minute
	data := session.NewData("sid", tokens, nil)
	err := rpHandler.SetSessionFallback(writer, r, data, expiresIn)
	assert.NoError(t, err)

	cookies := writer.Result().Cookies()

	for _, test := range []struct {
		cookieName string
		want       string
	}{
		{
			cookieName: "wonderwall-1",
			want:       "sid",
		},
		{
			cookieName: "wonderwall-2",
			want:       tokens.IDToken.GetSerialized(),
		},
		{
			cookieName: "wonderwall-3",
			want:       tokens.AccessToken,
		},
	} {
		assertCookieExists(t, rpHandler, test.cookieName, test.want, cookies)
	}
}

func TestHandler_DeleteSessionFallback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpHandler := idp.RelyingPartyHandler
	tokens := makeTokens(idp.Provider)

	t.Run("expire cookies if they are set", func(t *testing.T) {
		r := makeRequestWithFallbackCookies(t, idp, tokens)
		writer := httptest.NewRecorder()
		rpHandler.DeleteSessionFallback(writer, r)
		cookies := writer.Result().Cookies()

		assert.NotEmpty(t, cookies)
		assert.Len(t, cookies, 3)

		assertCookieExpired(t, "wonderwall-1", cookies)
		assertCookieExpired(t, "wonderwall-2", cookies)
		assertCookieExpired(t, "wonderwall-3", cookies)
	})

	t.Run("skip expiring cookies if they are not set", func(t *testing.T) {
		writer := httptest.NewRecorder()
		r := idp.GetRequest("/")
		rpHandler.DeleteSessionFallback(writer, r)
		cookies := writer.Result().Cookies()

		assert.Empty(t, cookies)
	})
}

func makeRequestWithFallbackCookies(t *testing.T, idp *mock.IdentityProvider, tokens *openid.Tokens) *http.Request {
	writer := httptest.NewRecorder()
	r := mock.NewGetRequest("/", idp.OpenIDConfig)

	expiresIn := time.Minute
	data := session.NewData("sid", tokens, nil)
	err := idp.RelyingPartyHandler.SetSessionFallback(writer, r, data, expiresIn)
	assert.NoError(t, err)

	cookies := writer.Result().Cookies()

	externalSessionIDCookie := getCookieFromJar("wonderwall-1", cookies)
	assert.NotNil(t, externalSessionIDCookie)
	idTokenCookie := getCookieFromJar("wonderwall-2", cookies)
	assert.NotNil(t, idTokenCookie)
	accessTokenCookie := getCookieFromJar("wonderwall-3", cookies)
	assert.NotNil(t, accessTokenCookie)

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

func assertCookieExists(t *testing.T, h *handler.Handler, cookieName, expectedValue string, cookies []*http.Cookie) {
	desiredCookie := getCookieFromJar(cookieName, cookies)
	assert.NotNil(t, desiredCookie)

	ciphertext, err := base64.StdEncoding.DecodeString(desiredCookie.Value)
	assert.NoError(t, err)

	plainbytes, err := h.Crypter.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, expectedValue, string(plainbytes))
}

func makeTokens(provider *mock.TestProvider) *openid.Tokens {
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

	accessToken := "some-access-token"

	return &openid.Tokens{
		IDToken:     openid.NewIDToken(string(signedIdToken), parsedIdToken),
		AccessToken: accessToken,
	}
}
