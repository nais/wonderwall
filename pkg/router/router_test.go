package router_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/router"
)

func TestHandler_Login(t *testing.T) {
	idpserver, idp := mock.IdentityProviderServer()
	h := mock.NewHandler(idp)
	r := router.New(h)

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)

	server := httptest.NewServer(r)
	client := server.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	loginURL, err := url.Parse(server.URL + "/oauth2/login")
	assert.NoError(t, err)

	resp, err := client.Get(loginURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	cookies := client.Jar.Cookies(loginURL)
	loginCookie := getCookieFromJar(cookie.Login, cookies)
	assert.NotNil(t, loginCookie)
	loginLegacyCookie := getCookieFromJar(cookie.LoginLegacy, cookies)
	assert.NotNil(t, loginLegacyCookie)

	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	assert.Equal(t, idpserver.URL, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
	assert.Equal(t, "/authorize", u.Path)
	assert.Equal(t, idp.GetClientConfiguration().GetACRValues(), u.Query().Get("acr_values"))
	assert.Equal(t, idp.GetClientConfiguration().GetUILocales(), u.Query().Get("ui_locales"))
	assert.Equal(t, idp.GetClientConfiguration().GetClientID(), u.Query().Get("client_id"))
	assert.Equal(t, idp.GetClientConfiguration().GetCallbackURI(), u.Query().Get("redirect_uri"))
	assert.NotEmpty(t, u.Query().Get("state"))
	assert.NotEmpty(t, u.Query().Get("nonce"))
	assert.NotEmpty(t, u.Query().Get("code_challenge"))

	resp, err = client.Get(u.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	location = resp.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	assert.Equal(t, u.Query().Get("state"), callbackURL.Query().Get("state"))
	assert.NotEmpty(t, callbackURL.Query().Get("code"))
}

func TestHandler_Callback_and_Logout(t *testing.T) {
	idpserver, idp := mock.IdentityProviderServer()

	h := mock.NewHandler(idp)
	r := router.New(h)
	server := httptest.NewServer(r)

	idp.ClientConfiguration.CallbackURI = server.URL + "/oauth2/callback"
	idp.ClientConfiguration.PostLogoutRedirectURI = server.URL
	idp.ClientConfiguration.LogoutCallbackURI = server.URL + "/oauth2/logout/callback"
	h.Client = mock.NewClient(idp)

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)

	client := server.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// First, run /oauth2/login to set cookies
	loginURL, err := url.Parse(server.URL + "/oauth2/login")
	resp, err := client.Get(loginURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	cookies := client.Jar.Cookies(loginURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)
	loginCookie := getCookieFromJar(cookie.Login, cookies)
	loginLegacyCookie := getCookieFromJar(cookie.LoginLegacy, cookies)

	assert.Nil(t, sessionCookie)
	assert.NotNil(t, loginCookie)
	assert.NotNil(t, loginLegacyCookie)

	// Get authorization URL
	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to authorize with identity provider
	resp, err = client.Get(u.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get callback URL after successful auth
	location = resp.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to callback
	resp, err = client.Get(callbackURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	cookies = client.Jar.Cookies(callbackURL)
	sessionCookie = getCookieFromJar(cookie.Session, cookies)
	loginCookie = getCookieFromJar(cookie.Login, cookies)
	loginLegacyCookie = getCookieFromJar(cookie.LoginLegacy, cookies)

	assert.NotNil(t, sessionCookie)
	assert.Nil(t, loginCookie)
	assert.Nil(t, loginLegacyCookie)

	// Request self-initiated logout
	logoutURL, err := url.Parse(server.URL + "/oauth2/logout")
	assert.NoError(t, err)

	resp, err = client.Get(logoutURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	cookies = client.Jar.Cookies(logoutURL)
	sessionCookie = getCookieFromJar(cookie.Session, cookies)
	logoutCookie := getCookieFromJar(cookie.Logout, cookies)

	assert.Nil(t, sessionCookie)
	assert.NotNil(t, logoutCookie)

	// Get endsession endpoint after local logout
	location = resp.Header.Get("location")
	endsessionURL, err := url.Parse(location)
	assert.NoError(t, err)

	idpserverURL, err := url.Parse(idpserver.URL)
	assert.NoError(t, err)

	endsessionParams := endsessionURL.Query()
	expectedState := endsessionParams["state"]
	assert.Equal(t, idpserverURL.Host, endsessionURL.Host)
	assert.Equal(t, "/endsession", endsessionURL.Path)
	assert.Equal(t, endsessionParams["post_logout_redirect_uri"], []string{idp.GetClientConfiguration().GetLogoutCallbackURI()})
	assert.NotEmpty(t, endsessionParams["id_token_hint"])
	assert.NotEmpty(t, expectedState)

	// Follow redirect to endsession endpoint at identity provider
	resp, err = client.Get(endsessionURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get post-logout redirect URI after successful logout at identity provider
	location = resp.Header.Get("location")
	logoutCallbackURI, err := url.Parse(location)
	assert.NoError(t, err)
	assert.Contains(t, logoutCallbackURI.String(), idp.ClientConfiguration.GetLogoutCallbackURI())
	logoutCallbackParams := endsessionURL.Query()
	actualState := logoutCallbackParams["state"]

	assert.Equal(t, "/oauth2/logout/callback", logoutCallbackURI.Path)
	assert.NotEmpty(t, actualState)
	assert.Equal(t, expectedState, actualState)

	// Follow redirect back to logout callback
	resp, err = client.Get(logoutCallbackURI.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	// Get post-logout redirect URI after redirect back to logout callback
	location = resp.Header.Get("location")
	postLogoutRedirectURI, err := url.Parse(location)
	assert.NoError(t, err)
	assert.Equal(t, idp.ClientConfiguration.GetPostLogoutRedirectURI(), postLogoutRedirectURI.String())

	cookies = client.Jar.Cookies(logoutCallbackURI)
	sessionCookie = getCookieFromJar(cookie.Session, cookies)
	logoutCookie = getCookieFromJar(cookie.Logout, cookies)

	assert.Nil(t, sessionCookie)
	assert.Nil(t, logoutCookie)
}

func TestHandler_FrontChannelLogout(t *testing.T) {
	_, idp := mock.IdentityProviderServer()
	idp.WithFrontChannelLogoutSupport()

	h := mock.NewHandler(idp)
	r := router.New(h)
	server := httptest.NewServer(r)

	idp.ClientConfiguration.CallbackURI = server.URL + "/oauth2/callback"
	idp.ClientConfiguration.PostLogoutRedirectURI = server.URL
	h.Client = mock.NewClient(idp)

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)

	client := server.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// First, run /oauth2/login to set cookies
	resp, err := client.Get(server.URL + "/oauth2/login")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get authorization URL
	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to authorize with idporten
	resp, err = client.Get(u.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get callback URL after successful auth
	location = resp.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to callback
	resp, err = client.Get(callbackURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	cookies := client.Jar.Cookies(callbackURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

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
	values.Add("iss", idp.GetOpenIDConfiguration().Issuer)
	frontchannelLogoutURL.RawQuery = values.Encode()

	resp, err = client.Get(frontchannelLogoutURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
}

func TestHandler_SessionStateRequired(t *testing.T) {
	idpServer, idp := mock.IdentityProviderServer()
	idp.WithCheckSessionIFrameSupport(idpServer.URL + "/checksession")
	h := mock.NewHandler(idp)
	r := router.New(h)
	server := httptest.NewServer(r)

	idp.ClientConfiguration.CallbackURI = server.URL + "/oauth2/callback"
	idp.ClientConfiguration.PostLogoutRedirectURI = server.URL
	h.Client = mock.NewClient(idp)

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)

	client := server.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// First, run /oauth2/login to set cookies
	resp, err := client.Get(server.URL + "/oauth2/login")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get authorization URL
	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to authorize with idporten
	resp, err = client.Get(u.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get callback URL after successful auth
	location = resp.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	params := callbackURL.Query()
	sessionState := params.Get("session_state")
	assert.NotEmpty(t, sessionState)
}

func getCookieFromJar(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}
