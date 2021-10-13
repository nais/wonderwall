package router_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

const clientID = "clientid"

var encryptionKey = []byte(`G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`) // 256 bits AES

var clients = map[string]string{
	clientID: "http://localhost/oauth2/logout/frontchannel",
}

func defaultConfig() config.Config {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key, err := jwk.New(privateKey)
	if err != nil {
		panic(err)
	}
	key.Set(jwk.AlgorithmKey, jwa.RS256)
	key.Set(jwk.KeyTypeKey, jwa.RSA)
	key.Set(jwk.KeyIDKey, uuid.New().String())

	clientJwk, err := json.Marshal(key)
	if err != nil {
		panic(err)
	}

	return config.Config{IDPorten: config.IDPorten{
		ClientID:     clientID,
		ClientJWK:    string(clientJwk),
		RedirectURI:  "http://localhost/callback",
		WellKnownURL: "",
		WellKnown: config.IDPortenWellKnown{
			Issuer:                "issuer",
			AuthorizationEndpoint: "http://localhost:1234/authorize",
			ACRValuesSupported:    config.Supported{"Level3", "Level4"},
			UILocalesSupported:    config.Supported{"nb", "nb", "en", "se"},
		},
		Locale: config.IDPortenLocale{
			Enabled: true,
			Value:   "nb",
		},
		SecurityLevel: config.IDPortenSecurityLevel{
			Enabled: true,
			Value:   "Level4",
		},
		PostLogoutRedirectURI: "",
		SessionMaxLifetime:    time.Hour,
	}}
}

func handler(cfg config.Config) *router.Handler {
	var jwkSet jwk.Set
	var err error

	if len(cfg.IDPorten.WellKnown.JwksURI) == 0 {
		jwk.NewSet()
	} else {
		jwkSet, err = jwk.Fetch(context.Background(), cfg.IDPorten.WellKnown.JwksURI)
	}
	if err != nil {
		panic(err)
	}

	crypter := cryptutil.New(encryptionKey)
	sessionStore := session.NewMemory()

	handler, err := router.NewHandler(cfg, crypter, zerolog.Logger{}, jwkSet, sessionStore, "")
	if err != nil {
		panic(err)
	}
	return handler.WithSecureCookie(false)
}

func TestHandler_Login(t *testing.T) {
	cfg := defaultConfig()

	h := handler(cfg)
	r := router.New(h)

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)

	server := httptest.NewServer(r)
	client := server.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	idprouter := mock.IDPortenRouter(mock.NewIDPorten(clients, cfg.IDPorten))
	idpserver := httptest.NewServer(idprouter)

	h.Config.IDPorten.WellKnown.AuthorizationEndpoint = idpserver.URL + "/authorize"

	loginURL, err := url.Parse(server.URL + "/oauth2/login")
	assert.NoError(t, err)

	req, err := client.Get(loginURL.String())
	assert.NoError(t, err)
	defer req.Body.Close()

	cookies := client.Jar.Cookies(loginURL)
	loginCookie := getCookieFromJar(h.GetLoginCookieName(), cookies)
	assert.NotNil(t, loginCookie)

	location := req.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	assert.Equal(t, idpserver.URL, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
	assert.Equal(t, "/authorize", u.Path)
	assert.Equal(t, cfg.IDPorten.SecurityLevel.Value, u.Query().Get("acr_values"))
	assert.Equal(t, cfg.IDPorten.Locale.Value, u.Query().Get("ui_locales"))
	assert.Equal(t, cfg.IDPorten.ClientID, u.Query().Get("client_id"))
	assert.Equal(t, cfg.IDPorten.RedirectURI, u.Query().Get("redirect_uri"))
	assert.NotEmpty(t, u.Query().Get("state"))
	assert.NotEmpty(t, u.Query().Get("nonce"))
	assert.NotEmpty(t, u.Query().Get("code_challenge"))

	req, err = client.Get(u.String())
	assert.NoError(t, err)
	defer req.Body.Close()

	location = req.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	assert.Equal(t, u.Query().Get("state"), callbackURL.Query().Get("state"))
	assert.NotEmpty(t, callbackURL.Query().Get("code"))
}

func TestHandler_Callback_and_Logout(t *testing.T) {
	cfg := defaultConfig()

	idprouter := mock.IDPortenRouter(mock.NewIDPorten(clients, cfg.IDPorten))
	idpserver := httptest.NewServer(idprouter)
	cfg.IDPorten.WellKnown.JwksURI = idpserver.URL + "/jwks"
	cfg.IDPorten.WellKnown.AuthorizationEndpoint = idpserver.URL + "/authorize"
	cfg.IDPorten.WellKnown.TokenEndpoint = idpserver.URL + "/token"
	cfg.IDPorten.WellKnown.EndSessionEndpoint = idpserver.URL + "/endsession"

	h := handler(cfg)
	r := router.New(h)
	server := httptest.NewServer(r)

	h.Config.IDPorten.RedirectURI = server.URL + "/oauth2/callback"
	h.Config.IDPorten.PostLogoutRedirectURI = server.URL

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)

	client := server.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// First, run /oauth2/login to set cookies
	loginURL, err := url.Parse(server.URL + "/oauth2/login")
	req, err := client.Get(loginURL.String())
	assert.NoError(t, err)
	defer req.Body.Close()

	cookies := client.Jar.Cookies(loginURL)
	sessionCookie := getCookieFromJar(h.GetSessionCookieName(), cookies)
	loginCookie := getCookieFromJar(h.GetLoginCookieName(), cookies)

	assert.Nil(t, sessionCookie)
	assert.NotNil(t, loginCookie)

	// Get authorization URL
	location := req.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to authorize with idporten
	req, err = client.Get(u.String())
	assert.NoError(t, err)
	defer req.Body.Close()

	// Get callback URL after successful auth
	location = req.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to callback
	req, err = client.Get(callbackURL.String())
	assert.NoError(t, err)

	cookies = client.Jar.Cookies(callbackURL)
	sessionCookie = getCookieFromJar(h.GetSessionCookieName(), cookies)
	loginCookie = getCookieFromJar(h.GetLoginCookieName(), cookies)

	assert.NotNil(t, sessionCookie)
	assert.Nil(t, loginCookie)

	// Request self-initiated logout
	logoutURL, err := url.Parse(server.URL + "/oauth2/logout")
	assert.NoError(t, err)

	req, err = client.Get(logoutURL.String())
	assert.NoError(t, err)
	defer req.Body.Close()

	cookies = client.Jar.Cookies(logoutURL)
	sessionCookie = getCookieFromJar(h.GetSessionCookieName(), cookies)

	assert.Nil(t, sessionCookie)

	// Get endsession endpoint after local logout
	location = req.Header.Get("location")
	endsessionURL, err := url.Parse(location)
	assert.NoError(t, err)

	idpserverURL, err := url.Parse(idpserver.URL)
	assert.NoError(t, err)

	endsessionParams := endsessionURL.Query()

	assert.Equal(t, idpserverURL.Host, endsessionURL.Host)
	assert.Equal(t, "/endsession", endsessionURL.Path)
	assert.Equal(t, endsessionParams["post_logout_redirect_uri"], []string{h.Config.IDPorten.PostLogoutRedirectURI})
	assert.NotEmpty(t, endsessionParams["id_token_hint"])
}

func TestHandler_FrontChannelLogout(t *testing.T) {
	cfg := defaultConfig()

	idp := mock.NewIDPorten(clients, cfg.IDPorten)
	idprouter := mock.IDPortenRouter(idp)
	idpserver := httptest.NewServer(idprouter)

	cfg.IDPorten.WellKnown.JwksURI = idpserver.URL + "/jwks"
	cfg.IDPorten.WellKnown.AuthorizationEndpoint = idpserver.URL + "/authorize"
	cfg.IDPorten.WellKnown.TokenEndpoint = idpserver.URL + "/token"

	h := handler(cfg)
	r := router.New(h)
	server := httptest.NewServer(r)

	h.Config.IDPorten.RedirectURI = server.URL + "/oauth2/callback"
	h.Config.IDPorten.PostLogoutRedirectURI = server.URL

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)

	client := server.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// First, run /oauth2/login to set cookies
	req, err := client.Get(server.URL + "/oauth2/login")
	assert.NoError(t, err)
	defer req.Body.Close()

	// Get authorization URL
	location := req.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to authorize with idporten
	req, err = client.Get(u.String())
	assert.NoError(t, err)
	defer req.Body.Close()

	// Get callback URL after successful auth
	location = req.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to callback
	req, err = client.Get(callbackURL.String())
	assert.NoError(t, err)

	cookies := client.Jar.Cookies(callbackURL)
	sessionCookie := getCookieFromJar(h.GetSessionCookieName(), cookies)

	assert.NotNil(t, sessionCookie)

	// Trigger front-channel logout
	ciphertext, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
	assert.NoError(t, err)

	sid, err := h.Crypter.Decrypt(ciphertext)
	assert.NoError(t, err)

	frontchannelLogoutURL, err := url.Parse(server.URL)
	assert.NoError(t, err)

	frontchannelLogoutURL.Path = "/oauth2/logout/frontchannel"

	values := url.Values{}
	values.Add("sid", string(sid))
	values.Add("iss", h.Config.IDPorten.WellKnown.Issuer)
	frontchannelLogoutURL.RawQuery = values.Encode()

	req, err = client.Get(frontchannelLogoutURL.String())
	assert.NoError(t, err)
	defer req.Body.Close()

	assert.Equal(t, http.StatusOK, req.StatusCode)
}

func getCookieFromJar(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}
