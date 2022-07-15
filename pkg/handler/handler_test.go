package handler_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/mock"
)

func TestHandler_Login(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	resp := localLogin(t, rpClient, idp)

	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	assert.Equal(t, idp.ProviderServer.URL, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
	assert.Equal(t, "/authorize", u.Path)
	assert.Equal(t, idp.OpenIDConfig.Client().GetACRValues(), u.Query().Get("acr_values"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetUILocales(), u.Query().Get("ui_locales"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetClientID(), u.Query().Get("client_id"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetCallbackURI(), u.Query().Get("redirect_uri"))
	assert.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	assert.ElementsMatch(t, idp.OpenIDConfig.Client().GetScopes(), strings.Split(u.Query().Get("scope"), " "))
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

func TestHandler_Callback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)
}

func TestHandler_Logout(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := localLogout(t, rpClient, idp)

	// Get endsession endpoint after local logout
	location := resp.Header.Get("location")
	endsessionURL, err := url.Parse(location)
	assert.NoError(t, err)

	idpserverURL, err := url.Parse(idp.ProviderServer.URL)
	assert.NoError(t, err)

	endsessionParams := endsessionURL.Query()
	assert.Equal(t, idpserverURL.Host, endsessionURL.Host)
	assert.Equal(t, "/endsession", endsessionURL.Path)
	assert.Equal(t, endsessionParams["post_logout_redirect_uri"], []string{idp.OpenIDConfig.Client().GetLogoutCallbackURI()})
	assert.NotEmpty(t, endsessionParams["id_token_hint"])
}

func TestHandler_LogoutCallback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	logout(t, rpClient, idp)
}

func TestHandler_FrontChannelLogout(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.Provider.WithFrontChannelLogoutSupport()
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	sessionCookie := login(t, rpClient, idp)

	// Trigger front-channel logout
	sid := func() string {
		ciphertext, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
		assert.NoError(t, err)

		localSessionID, err := idp.RelyingPartyHandler.Crypter.Decrypt(ciphertext)
		assert.NoError(t, err)

		encryptedSession, err := idp.RelyingPartyHandler.Sessions.Read(context.Background(), string(localSessionID))
		assert.NoError(t, err)

		data, err := encryptedSession.Decrypt(idp.RelyingPartyHandler.Crypter)
		assert.NoError(t, err)

		return data.ExternalSessionID
	}()

	frontchannelLogoutURL, err := url.Parse(idp.RelyingPartyServer.URL)
	assert.NoError(t, err)

	frontchannelLogoutURL.Path = "/oauth2/logout/frontchannel"

	values := url.Values{}
	values.Add("sid", sid)
	values.Add("iss", idp.OpenIDConfig.Provider().Issuer)
	frontchannelLogoutURL.RawQuery = values.Encode()

	resp, err := rpClient.Get(frontchannelLogoutURL.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_SessionStateRequired(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.Provider.WithCheckSessionIFrameSupport(idp.ProviderServer.URL + "/checksession")
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	resp := authorize(t, rpClient, idp)

	// Get callback URL after successful auth
	location := resp.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	params := callbackURL.Query()
	sessionState := params.Get("session_state")
	assert.NotEmpty(t, sessionState)
}

func TestHandler_Default(t *testing.T) {
	// TODO
}

func localLogin(t *testing.T, rpClient *http.Client, idp mock.IdentityProvider) *http.Response {
	// First, run /oauth2/login to set cookies
	loginURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/login")
	assert.NoError(t, err)

	resp, err := rpClient.Get(loginURL.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(loginURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)
	loginCookie := getCookieFromJar(cookie.Login, cookies)
	loginLegacyCookie := getCookieFromJar(cookie.LoginLegacy, cookies)

	assert.Nil(t, sessionCookie)
	assert.NotNil(t, loginCookie)
	assert.NotNil(t, loginLegacyCookie)

	return resp
}

func authorize(t *testing.T, rpClient *http.Client, idp mock.IdentityProvider) *http.Response {
	resp := localLogin(t, rpClient, idp)

	// Get authorization URL
	location := resp.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to authorize with identity provider
	resp, err = rpClient.Get(u.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	return resp
}

func callback(t *testing.T, rpClient *http.Client, authorizeResponse *http.Response) *http.Cookie {
	// Get callback URL after successful auth
	location := authorizeResponse.Header.Get("location")
	callbackURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to callback
	resp, err := rpClient.Get(callbackURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(callbackURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)
	loginCookie := getCookieFromJar(cookie.Login, cookies)
	loginLegacyCookie := getCookieFromJar(cookie.LoginLegacy, cookies)

	assert.NotNil(t, sessionCookie)
	assert.Nil(t, loginCookie)
	assert.Nil(t, loginLegacyCookie)

	return sessionCookie
}

func login(t *testing.T, rpClient *http.Client, idp mock.IdentityProvider) *http.Cookie {
	resp := authorize(t, rpClient, idp)
	return callback(t, rpClient, resp)
}

func localLogout(t *testing.T, rpClient *http.Client, idp mock.IdentityProvider) *http.Response {
	// Request self-initiated logout
	logoutURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/logout")
	assert.NoError(t, err)

	resp, err := rpClient.Get(logoutURL.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(logoutURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)

	return resp
}

func logout(t *testing.T, rpClient *http.Client, idp mock.IdentityProvider) {
	resp := localLogout(t, rpClient, idp)

	// Get endsession endpoint after local logout
	location := resp.Header.Get("location")
	endsessionURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Follow redirect to endsession endpoint at identity provider
	resp, err = rpClient.Get(endsessionURL.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

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

	cookies := rpClient.Jar.Cookies(logoutCallbackURI)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)
}

func getCookieFromJar(name string, cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}

	return nil
}
