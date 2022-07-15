package handler_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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
	defer resp.Body.Close()

	loginURL, err := resp.Location()
	assert.NoError(t, err)

	assert.Equal(t, idp.ProviderServer.URL, fmt.Sprintf("%s://%s", loginURL.Scheme, loginURL.Host))
	assert.Equal(t, "/authorize", loginURL.Path)
	assert.Equal(t, idp.OpenIDConfig.Client().GetACRValues(), loginURL.Query().Get("acr_values"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetUILocales(), loginURL.Query().Get("ui_locales"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetClientID(), loginURL.Query().Get("client_id"))
	assert.Equal(t, idp.OpenIDConfig.Client().GetCallbackURI(), loginURL.Query().Get("redirect_uri"))
	assert.Equal(t, "S256", loginURL.Query().Get("code_challenge_method"))
	assert.ElementsMatch(t, idp.OpenIDConfig.Client().GetScopes(), strings.Split(loginURL.Query().Get("scope"), " "))
	assert.NotEmpty(t, loginURL.Query().Get("state"))
	assert.NotEmpty(t, loginURL.Query().Get("nonce"))
	assert.NotEmpty(t, loginURL.Query().Get("code_challenge"))

	resp, err = rpClient.Get(loginURL.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	callbackURL, err := resp.Location()
	assert.NoError(t, err)

	assert.Equal(t, loginURL.Query().Get("state"), callbackURL.Query().Get("state"))
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
	defer resp.Body.Close()

	// Get endsession endpoint after local logout
	endsessionURL, err := resp.Location()
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
	defer resp.Body.Close()

	// Get callback URL after successful auth
	callbackURL, err := resp.Location()
	assert.NoError(t, err)

	params := callbackURL.Query()
	sessionState := params.Get("session_state")
	assert.NotEmpty(t, sessionState)
}

func TestHandler_Default(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")

		if len(token) > 0 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("not ok"))
		}
	})
	upstream := httptest.NewServer(upstreamHandler)
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	assert.NoError(t, err)

	t.Run("without auto-login", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = upstreamURL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		rpClient := idp.RelyingPartyClient()

		// initial request without session
		resp, err := rpClient.Get(idp.RelyingPartyServer.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "not ok", string(body))

		// acquire session
		login(t, rpClient, idp)

		// retry request with session
		resp, err = rpClient.Get(idp.RelyingPartyServer.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err = ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "ok", string(body))
	})

	t.Run("with auto-login", func(t *testing.T) {
		cfg := mock.Config()
		cfg.AutoLogin = true
		cfg.UpstreamHost = upstreamURL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		rpClient := idp.RelyingPartyClient()

		// initial request without session
		target := idp.RelyingPartyServer.URL + "/"

		resp, err := rpClient.Get(target)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// redirect should point to identity provider
		authorizeLocation, err := resp.Location()
		assert.NoError(t, err)
		authorizeEndpoint := *authorizeLocation
		authorizeEndpoint.RawQuery = ""
		assert.Equal(t, idp.OpenIDConfig.Provider().AuthorizationEndpoint, authorizeEndpoint.String())

		// follow redirect to identity provider for login
		resp, err = rpClient.Get(authorizeLocation.String())
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// redirect should point back to relying party
		callbackLocation, err := resp.Location()
		assert.NoError(t, err)
		callbackEndpoint := *callbackLocation
		callbackEndpoint.RawQuery = ""
		assert.Equal(t, idp.OpenIDConfig.Client().GetCallbackURI(), callbackEndpoint.String())

		// follow redirect back to relying party
		resp, err = rpClient.Get(callbackLocation.String())
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// finally, follow redirect back to original target, now with a session
		targetLocation, err := resp.Location()
		assert.NoError(t, err)
		assert.Equal(t, target, targetLocation.String())

		resp, err = rpClient.Get(targetLocation.String())
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "ok", string(body))
	})

	t.Run("with auto-login and skipped paths", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = upstreamURL.Host
		cfg.AutoLogin = true
		cfg.AutoLoginSkipPaths = []string{
			"^/exact/match$",
			"^/allowed(/?|/.*)$",
			"/partial/(yup|yes)",
		}
		err := cfg.Validate()
		assert.NoError(t, err)

		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		rpClient := idp.RelyingPartyClient()

		t.Run("matched paths", func(t *testing.T) {
			matched := []string{
				"/exact/match",
				"/allowed",
				"/allowed/",
				"/allowed/very",
				"/allowed/very/cool",
				"/partial/yes",
				"/partial/yup",
				"/partial/yes/no",
				"/partial/yup/no",
				"/parent/partial/yup/no",
			}
			for _, path := range matched {
				t.Run(path, func(t *testing.T) {
					resp, err := rpClient.Get(idp.RelyingPartyServer.URL + path)
					assert.NoError(t, err)
					defer resp.Body.Close()

					assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

					body, err := ioutil.ReadAll(resp.Body)
					assert.NoError(t, err)
					assert.Equal(t, "not ok", string(body))
				})
			}
		})

		t.Run("non-matched paths", func(t *testing.T) {
			nonMatched := []string{
				"",
				"/",
				"/exact/match/",
				"/exact/match/huh",
				"/not-allowed",
				"/not-allowed/allowed",
				"/alloweded",
				"/nope/partial/",
				"/nope/partial/child",
			}
			for _, path := range nonMatched {
				t.Run(path, func(t *testing.T) {
					resp, err := rpClient.Get(idp.RelyingPartyServer.URL + path)
					assert.NoError(t, err)
					defer resp.Body.Close()

					assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
				})
			}
		})
	})
}

func localLogin(t *testing.T, rpClient *http.Client, idp mock.IdentityProvider) *http.Response {
	// First, run /oauth2/login to set cookies
	loginURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/login")
	assert.NoError(t, err)

	resp, err := rpClient.Get(loginURL.String())
	assert.NoError(t, err)
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
	defer resp.Body.Close()

	authorizeURL, err := resp.Location()
	assert.NoError(t, err)

	// Follow redirect to authorize with identity provider
	resp, err = rpClient.Get(authorizeURL.String())
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	return resp
}

func callback(t *testing.T, rpClient *http.Client, authorizeResponse *http.Response) *http.Cookie {
	// Get callback URL after successful auth
	callbackURL, err := authorizeResponse.Location()
	assert.NoError(t, err)

	// Follow redirect to callback
	resp, err := rpClient.Get(callbackURL.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()

	// Get endsession endpoint after local logout
	endsessionURL, err := resp.Location()
	assert.NoError(t, err)

	// Follow redirect to endsession endpoint at identity provider
	resp, err = rpClient.Get(endsessionURL.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	// Get post-logout redirect URI after successful logout at identity provider
	logoutCallbackURI, err := resp.Location()
	assert.NoError(t, err)
	assert.Contains(t, logoutCallbackURI.String(), idp.OpenIDConfig.Client().GetLogoutCallbackURI())

	assert.Equal(t, "/oauth2/logout/callback", logoutCallbackURI.Path)

	// Follow redirect back to logout callback
	resp, err = rpClient.Get(logoutCallbackURI.String())
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	// Get post-logout redirect URI after redirect back to logout callback
	postLogoutRedirectURI, err := resp.Location()
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
