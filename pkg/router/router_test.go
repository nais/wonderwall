package router_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

const clientID = "clientid"

var encryptionKey = []byte(`G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`) // 256 bits AES

var clients = map[string]string{
	clientID: "http://localhost/oauth2/logout/frontchannel",
}

func defaultConfig() config.IDPorten {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key, err := jwk.New(privateKey)
	if err != nil {
		panic(err)
	}

	clientJwk, err := json.Marshal(key)
	if err != nil {
		panic(err)
	}

	return config.IDPorten{
		ClientID:     clientID,
		ClientJWK:    string(clientJwk),
		RedirectURI:  "http://localhost/callback",
		WellKnownURL: "",
		WellKnown: config.IDPortenWellKnown{
			Issuer:                "issuer",
			AuthorizationEndpoint: "http://localhost:1234/authorize",
		},
		Locale:                "nb",
		SecurityLevel:         "Level4",
		PostLogoutRedirectURI: "",
		SessionMaxLifetime:    time.Hour,
	}
}

func handler(cfg config.IDPorten) *router.Handler {
	var jwkSet jwk.Set
	var err error

	if len(cfg.WellKnown.JwksURI) == 0 {
		jwk.NewSet()
	} else {
		jwkSet, err = jwk.Fetch(context.Background(), cfg.WellKnown.JwksURI)
	}
	if err != nil {
		panic(err)
	}

	crypter := cryptutil.New(encryptionKey)
	sessionStore := session.NewMemory()

	handler, err := router.NewHandler(cfg, crypter, jwkSet, sessionStore, "")
	if err != nil {
		panic(err)
	}
	return handler.WithSecureCookie(false)
}

func TestLoginURL(t *testing.T) {
	handler := handler(defaultConfig())
	_, err := handler.LoginURL()
	assert.NoError(t, err)
}

func TestHandler_Login(t *testing.T) {
	cfg := defaultConfig()

	h := handler(cfg)
	prefixes := config.ParseIngresses([]string{""})
	r := router.New(h, prefixes)

	server := httptest.NewServer(r)
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	idprouter := idportenRouter(NewIDPorten(clients, cfg))
	idpserver := httptest.NewServer(idprouter)

	h.Config.WellKnown.AuthorizationEndpoint = idpserver.URL + "/authorize"

	req, err := client.Get(server.URL + "/oauth2/login")
	assert.NoError(t, err)
	defer req.Body.Close()

	location := req.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	assert.Equal(t, idpserver.URL, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
	assert.Equal(t, "/authorize", u.Path)
	assert.Equal(t, cfg.SecurityLevel, u.Query().Get("acr_values"))
	assert.Equal(t, cfg.Locale, u.Query().Get("ui_locales"))
	assert.Equal(t, cfg.ClientID, u.Query().Get("client_id"))
	assert.Equal(t, cfg.RedirectURI, u.Query().Get("redirect_uri"))
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

	idprouter := idportenRouter(NewIDPorten(clients, cfg))
	idpserver := httptest.NewServer(idprouter)
	cfg.WellKnown.JwksURI = idpserver.URL + "/jwks"
	cfg.WellKnown.AuthorizationEndpoint = idpserver.URL + "/authorize"
	cfg.WellKnown.TokenEndpoint = idpserver.URL + "/token"
	cfg.WellKnown.EndSessionEndpoint = idpserver.URL + "/endsession"

	h := handler(cfg)
	prefixes := config.ParseIngresses([]string{""})
	r := router.New(h, prefixes)
	server := httptest.NewServer(r)

	h.Config.RedirectURI = server.URL + "/oauth2/callback"
	h.Config.PostLogoutRedirectURI = server.URL

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
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == router.SessionCookieName {
			sessionCookie = cookie
		}
	}

	assert.NotNil(t, sessionCookie)

	// Request self-initiated logout
	req, err = client.Get(server.URL + "/oauth2/logout")
	assert.NoError(t, err)
	defer req.Body.Close()

	cookies = client.Jar.Cookies(callbackURL)
	for _, cookie := range cookies {
		if cookie.Name == router.SessionCookieName {
			sessionCookie = cookie
		}
	}

	assert.NotNil(t, sessionCookie)
	assert.Empty(t, sessionCookie.Value)
	assert.True(t, sessionCookie.Expires.Before(time.Now()))

	// Get endsession endpoint after local logout
	location = req.Header.Get("location")
	endsessionURL, err := url.Parse(location)
	assert.NoError(t, err)

	idpserverURL, err := url.Parse(idpserver.URL)
	assert.NoError(t, err)

	endsessionParams := endsessionURL.Query()

	assert.Equal(t, idpserverURL.Host, endsessionURL.Host)
	assert.Equal(t, "/endsession", endsessionURL.Path)
	assert.Equal(t, endsessionParams["post_logout_redirect_uri"], []string{h.Config.PostLogoutRedirectURI})
	assert.NotEmpty(t, endsessionParams["id_token_hint"])
}

func TestHandler_FrontChannelLogout(t *testing.T) {
	cfg := defaultConfig()

	idp := NewIDPorten(clients, cfg)
	idprouter := idportenRouter(idp)
	idpserver := httptest.NewServer(idprouter)

	cfg.WellKnown.JwksURI = idpserver.URL + "/jwks"
	cfg.WellKnown.AuthorizationEndpoint = idpserver.URL + "/authorize"
	cfg.WellKnown.TokenEndpoint = idpserver.URL + "/token"

	h := handler(cfg)
	prefixes := config.ParseIngresses([]string{""})
	r := router.New(h, prefixes)
	server := httptest.NewServer(r)

	h.Config.RedirectURI = server.URL + "/oauth2/callback"
	h.Config.PostLogoutRedirectURI = server.URL

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
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == router.SessionCookieName {
			sessionCookie = cookie
		}
	}

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
	values.Add("iss", h.Config.WellKnown.Issuer)
	frontchannelLogoutURL.RawQuery = values.Encode()

	req, err = client.Get(frontchannelLogoutURL.String())
	assert.NoError(t, err)
	defer req.Body.Close()
}
