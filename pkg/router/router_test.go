package router_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc"

	"github.com/nais/wonderwall/pkg/cryptutil"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/router"
)

const clientID = "clientid"

var encryptionKey = []byte(`G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`) // 256 bits AES

var cfg = config.IDPorten{
	ClientID: clientID,
	ClientJWK: `
{
  "kty": "RSA",
  "kid": "9rJ_0ziKoGNjSS_l11hn0yQxEqg",
  "n": "siUszyp3NOJlMMhguHxh6vLpMrFLRUSOx0FfjcBSIZ5QCPh6D4IpwhOW5yprKbApLPIse6qCo-cRwwzYhkXiSF7U8BSnpdp6orhtfHKBBfbYTljHXvQLQ7ADquFNXOl1KlK8A26ut6goYzxgOJ_QYOzshjTx_kNwYJb1DzKPNBxzAg-pOjwEbPKp3ErTlv46yE43gOYi_9wAmFBsA-oX8SiDBaYSmi6XDdaUx5XRpWkXwSdaJ2Hh5pky2fRRwLzQGTyyxAW_u4iyDgRf48C2eOtCc_fORc7vQkojrXWS366vQXNjp605al1H4zbq2YTOQI9YEL18EaQyoxUaxrUqVw",
  "e": "AQAB",
  "d": "eVbm6YjUP1pBcHPbpW1bSKwB-PxX96tV0RSPID8x8iIiA6ozgaK4DLBJJdV3vqJ1uV6OvAENENTP_VoflX2-PmsRgSGge1CQHYufT5eymDxlYyAHVH7HuWgHZ3oktrdxjc1isLfQG9pXABjctVTtm0dlZ5hiiDypK7FG4_4dGnFud74suZU1kXi-fQsf7W-VxO4LZ6BLyTrvjPecu91GtKpHezjNoP__cEhGF2KISspO9bvvTuwguJCaM0bg_nW1POlXggTUbV3tJbD5PYs929ExKgWpq3cZXRq0fG3bApJsquCFAOJjdJ_dF37sh5gveUEhFbciXUeVXMSYKdnsAQ",
  "p": "5v-xD0CqUlgIF51Q2puG8CEZNxVBtqJN-xrs9HH9Do6ObYrxjPPWVx_TJc7Os_q9hgAtMKhxEC-ssf3t5bOD6IUsiyiSJKNT5RZEgTdMAAKD_5p-BkXi9lhDKySGRf2r5V1qSYTTYzEx0HOn-ZSrOPK6psR3PI2fCdb_TfRn3gE",
  "q": "xW0QRv4Jd9KefgyF53nmeQ0eALcAIiWreKz8u96xdByl0RCbo6OAmoobgaWFT0_TdPzCIz1qwa_xT3_6xGhBBW5BXoLUaf86j6_WxQesIelC9ZfwNWdP0V17VBd8L94Y4kGw6VvI42P8FKrXA0MXSNmAMVMb8PrLvl9rrL_YuFc",
  "dp": "g67fUMKcVbS5aDzWCsj-c4VqymvjuilsKul-ixswF0xNBUVfzepzFdeelr7-NruJrwoKuOJNEd0bpZwMMhXT7Il-ixXlud0hxkabZs4PFTJZ7Sw1C35rk-Nc5ws7QEsL4wUNwjtmBfXVX--OokiOEzjMDqWRE4PoVcOqZtYdIAE",
  "dq": "PYtIPblHnlDME6M3wvcfP7E1HyftJLf1gkL67l33l6iukEPLIPIBTyuqc3nz2suZsahxpKaqtwJwCUZuF_gf_N9oBVxndzuXN9-q5fUEVfXvZ7wbp6ozGaM4pPhFQG7N9wpfaf-w2iH7HT48lMm_YnhbHAU6ep7UEN6SJGIR3zU",
  "qi": "juJsMNCw9y1aTCGxkGW-LkyumX5VfcigOr893gzYMkX7XuCupEp5Yk9IlDDjnLrbd6KU_ytZHK1ErPCekt3LDd7CnsYNYkWvHpFAS3tqF5DVGWUtZ82Z-0dDYZvjbCojHgG3eFUk5bJZkHxgNql6dKX9ro_LfaGwIJ4-beVQHG0",
  "x5t": "9rJ_0ziKoGNjSS_l11hn0yQxEqg"
}
`,
	RedirectURI:  "http://localhost/callback",
	WellKnownURL: "",
	WellKnown: config.IDPortenWellKnown{
		Issuer:                "issuer",
		AuthorizationEndpoint: "http://localhost:1234/authorize",
	},
	Locale:                "nb",
	SecurityLevel:         "Level4",
	PostLogoutRedirectURI: "",
}

var clients = map[string]string{
	clientID: "http://localhost/oauth2/logout/frontchannel",
}
var idp = NewIDPorten(clients)

func handler() *router.Handler {
	handler := router.Handler{
		Config: cfg,
		OauthConfig: oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "auth-url",
				TokenURL: "token-url",
			},
			RedirectURL: "redirect-url",
			Scopes:      []string{"scopes"},
		},
		Crypter:         cryptutil.New(encryptionKey),
		UpstreamHost:    "",
		IdTokenVerifier: nil,
	}
	handler.Init()
	return &handler
}

func TestLoginURL(t *testing.T) {
	handler := &router.Handler{
		Config: cfg,
	}
	_, err := handler.LoginURL()
	assert.NoError(t, err)
}

func TestHandler_Login(t *testing.T) {
	h := handler()
	r := router.New(h)

	server := httptest.NewServer(r)
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	idprouter := idportenRouter(idp)
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
	h := handler()
	r := router.New(h)
	server := httptest.NewServer(r)

	idprouter := idportenRouter(idp)
	idpserver := httptest.NewServer(idprouter)
	h.OauthConfig.Endpoint.TokenURL = idpserver.URL + "/token"
	h.Config.WellKnown.AuthorizationEndpoint = idpserver.URL + "/authorize"
	h.Config.WellKnown.EndSessionEndpoint = idpserver.URL + "/endsession"
	h.Config.RedirectURI = server.URL + "/oauth2/callback"
	h.Config.PostLogoutRedirectURI = server.URL
	h.IdTokenVerifier = oidc.NewVerifier(
		cfg.WellKnown.Issuer,
		oidc.NewRemoteKeySet(context.Background(), idpserver.URL+"/jwks"),
		&oidc.Config{ClientID: cfg.ClientID},
	)

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

	idpserverURL.Path = "/endsession"
	values := url.Values{}
	values.Add("post_logout_redirect_uri", h.Config.PostLogoutRedirectURI)

	idpserverURL.RawQuery = values.Encode()

	assert.Equal(t, idpserverURL, endsessionURL)
}

func TestHandler_FrontChannelLogout(t *testing.T) {
	h := handler()
	r := router.New(h)
	server := httptest.NewServer(r)

	idprouter := idportenRouter(idp)
	idpserver := httptest.NewServer(idprouter)
	h.OauthConfig.Endpoint.TokenURL = idpserver.URL + "/token"
	h.Config.WellKnown.AuthorizationEndpoint = idpserver.URL + "/authorize"
	h.Config.WellKnown.EndSessionEndpoint = idpserver.URL + "/endsession"
	h.Config.RedirectURI = server.URL + "/oauth2/callback"
	h.Config.PostLogoutRedirectURI = server.URL
	h.IdTokenVerifier = oidc.NewVerifier(
		cfg.WellKnown.Issuer,
		oidc.NewRemoteKeySet(context.Background(), idpserver.URL+"/jwks"),
		&oidc.Config{ClientID: cfg.ClientID},
	)

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
