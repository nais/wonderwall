package router_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestHandler_Login(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	loginURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/login")
	assert.NoError(t, err)

	resp, err := rpClient.Get(loginURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	cookies := rpClient.Jar.Cookies(loginURL)
	loginCookie := getCookieFromJar(cookie.Login, cookies)
	assert.NotNil(t, loginCookie)
	loginLegacyCookie := getCookieFromJar(cookie.LoginLegacy, cookies)
	assert.NotNil(t, loginLegacyCookie)

	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	assert.Equal(t, idp.ProviderServer.URL, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
	assert.Equal(t, "/authorize", u.Path)
	assert.Equal(t, idp.OpenIDConfig.Client().GetACRValues(), u.Query().Get("acr_values"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetUILocales(), u.Query().Get("ui_locales"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetClientID(), u.Query().Get("client_id"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetCallbackURI(), u.Query().Get("redirect_uri"))
	assert.NotEmpty(t, u.Query().Get("state"))
	assert.NotEmpty(t, u.Query().Get("nonce"))
	assert.NotEmpty(t, u.Query().Get("code_challenge"))

	resp, err = rpClient.Get(u.String())
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
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	idp.OpenIDConfig.ClientConfig.CallbackURI = idp.RelyingPartyServer.URL + "/oauth2/callback"
	idp.OpenIDConfig.ClientConfig.PostLogoutRedirectURI = idp.RelyingPartyServer.URL
	idp.OpenIDConfig.ClientConfig.LogoutCallbackURI = idp.RelyingPartyServer.URL + "/oauth2/logout/callback"

	c := client.NewClient(idp.OpenIDConfig)
	idp.RelyingPartyHandler.Client = c

	// First, run /oauth2/login to set cookies
	loginURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/login")
	resp, err := rpClient.Get(loginURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	cookies := rpClient.Jar.Cookies(loginURL)
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
	resp, err = rpClient.Get(u.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get callback URL after successful auth
	location = resp.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to callback
	resp, err = rpClient.Get(callbackURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	cookies = rpClient.Jar.Cookies(callbackURL)
	sessionCookie = getCookieFromJar(cookie.Session, cookies)
	loginCookie = getCookieFromJar(cookie.Login, cookies)
	loginLegacyCookie = getCookieFromJar(cookie.LoginLegacy, cookies)

	assert.NotNil(t, sessionCookie)
	assert.Nil(t, loginCookie)
	assert.Nil(t, loginLegacyCookie)

	// Request self-initiated logout
	logoutURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/logout")
	assert.NoError(t, err)

	resp, err = rpClient.Get(logoutURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	cookies = rpClient.Jar.Cookies(logoutURL)
	sessionCookie = getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)

	// Get endsession endpoint after local logout
	location = resp.Header.Get("location")
	endsessionURL, err := url.Parse(location)
	assert.NoError(t, err)

	idpserverURL, err := url.Parse(idp.ProviderServer.URL)
	assert.NoError(t, err)

	endsessionParams := endsessionURL.Query()
	assert.Equal(t, idpserverURL.Host, endsessionURL.Host)
	assert.Equal(t, "/endsession", endsessionURL.Path)
	assert.Equal(t, endsessionParams["post_logout_redirect_uri"], []string{idp.OpenIDConfig.Client().GetLogoutCallbackURI()})
	assert.NotEmpty(t, endsessionParams["id_token_hint"])

	// Follow redirect to endsession endpoint at identity provider
	resp, err = rpClient.Get(endsessionURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get post-logout redirect URI after successful logout at identity provider
	location = resp.Header.Get("location")
	logoutCallbackURI, err := url.Parse(location)
	assert.NoError(t, err)
	assert.Contains(t, logoutCallbackURI.String(), idp.OpenIDConfig.Client().GetLogoutCallbackURI())

	assert.Equal(t, "/oauth2/logout/callback", logoutCallbackURI.Path)

	// Follow redirect back to logout callback
	resp, err = rpClient.Get(logoutCallbackURI.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	// Get post-logout redirect URI after redirect back to logout callback
	location = resp.Header.Get("location")
	postLogoutRedirectURI, err := url.Parse(location)
	assert.NoError(t, err)
	assert.Equal(t, idp.OpenIDConfig.Client().GetPostLogoutRedirectURI(), postLogoutRedirectURI.String())

	cookies = rpClient.Jar.Cookies(logoutCallbackURI)
	sessionCookie = getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)
}

func TestHandler_FrontChannelLogout(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.Provider.WithFrontChannelLogoutSupport()
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	idp.OpenIDConfig.ClientConfig.CallbackURI = idp.RelyingPartyServer.URL + "/oauth2/callback"
	idp.OpenIDConfig.ClientConfig.PostLogoutRedirectURI = idp.RelyingPartyServer.URL

	c := client.NewClient(idp.OpenIDConfig)
	idp.RelyingPartyHandler.Client = c

	// First, run /oauth2/login to set cookies
	resp, err := rpClient.Get(idp.RelyingPartyServer.URL + "/oauth2/login")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get authorization URL
	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to authorize with idporten
	resp, err = rpClient.Get(u.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get callback URL after successful auth
	location = resp.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to callback
	resp, err = rpClient.Get(callbackURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(callbackURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

	assert.NotNil(t, sessionCookie)

	// Trigger front-channel logout
	ciphertext, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
	assert.NoError(t, err)

	sid, err := idp.RelyingPartyHandler.Crypter.Decrypt(ciphertext)
	assert.NoError(t, err)

	frontchannelLogoutURL, err := url.Parse(idp.RelyingPartyServer.URL)
	assert.NoError(t, err)

	frontchannelLogoutURL.Path = "/oauth2/logout/frontchannel"

	values := url.Values{}
	values.Add("sid", string(sid))
	values.Add("iss", idp.OpenIDConfig.Provider().Issuer)
	frontchannelLogoutURL.RawQuery = values.Encode()

	resp, err = rpClient.Get(frontchannelLogoutURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
}

func TestHandler_SessionStateRequired(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.Provider.WithCheckSessionIFrameSupport(idp.ProviderServer.URL + "/checksession")
	defer idp.Close()

	idp.OpenIDConfig.ClientConfig.CallbackURI = idp.RelyingPartyServer.URL + "/oauth2/callback"
	idp.OpenIDConfig.ClientConfig.PostLogoutRedirectURI = idp.RelyingPartyServer.URL

	c := client.NewClient(idp.OpenIDConfig)
	idp.RelyingPartyHandler.Client = c

	rpClient := idp.RelyingPartyClient()

	// First, run /oauth2/login to set cookies
	resp, err := rpClient.Get(idp.RelyingPartyServer.URL + "/oauth2/login")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	defer resp.Body.Close()

	// Get authorization URL
	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to authorize with idporten
	resp, err = rpClient.Get(u.String())
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
