package handler_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/session"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

func TestLogin(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	resp := localLogin(t, rpClient, idp)
	loginURL := resp.Location

	req := idp.GetRequest(idp.RelyingPartyServer.URL + "/oauth2/login")

	expectedCallbackURL, err := urlpkg.LoginCallback(req)
	assert.NoError(t, err)

	assert.Equal(t, idp.ProviderServer.URL, fmt.Sprintf("%s://%s", loginURL.Scheme, loginURL.Host))
	assert.Equal(t, "/authorize", loginURL.Path)
	assert.Equal(t, idp.OpenIDConfig.Client().ACRValues(), loginURL.Query().Get("acr_values"))
	assert.Equal(t, idp.OpenIDConfig.Client().UILocales(), loginURL.Query().Get("ui_locales"))
	assert.Equal(t, idp.OpenIDConfig.Client().ClientID(), loginURL.Query().Get("client_id"))
	assert.Equal(t, expectedCallbackURL, loginURL.Query().Get("redirect_uri"))
	assert.Equal(t, "S256", loginURL.Query().Get("code_challenge_method"))
	assert.ElementsMatch(t, idp.OpenIDConfig.Client().Scopes(), strings.Split(loginURL.Query().Get("scope"), " "))
	assert.NotEmpty(t, loginURL.Query().Get("state"))
	assert.NotEmpty(t, loginURL.Query().Get("nonce"))
	assert.NotEmpty(t, loginURL.Query().Get("code_challenge"))

	resp = get(t, rpClient, loginURL.String())
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	callbackURL := resp.Location
	assert.Equal(t, loginURL.Query().Get("state"), callbackURL.Query().Get("state"))
	assert.NotEmpty(t, callbackURL.Query().Get("code"))
}

func TestLoginPrompt(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	// initial login and callback
	initialSessionCookie := login(t, rpClient, idp)

	// verify session created
	sess := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, sess.StatusCode)

	// trigger authorize with prompt=login
	loginURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/login?prompt=login")
	assert.NoError(t, err)
	loginResp := get(t, rpClient, loginURL.String())
	assert.Equal(t, http.StatusFound, loginResp.StatusCode)

	cookies := rpClient.Jar.Cookies(loginURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)
	loginCookie := getCookieFromJar(cookie.Login, cookies)

	assert.Nil(t, sessionCookie)
	assert.NotNil(t, loginCookie)

	// verify session deleted
	sess = sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusUnauthorized, sess.StatusCode)

	// follow redirect to idp
	authorizeResp := get(t, rpClient, loginResp.Location.String())
	assert.Equal(t, http.StatusFound, authorizeResp.StatusCode)

	// follow callback back to rp
	sessionCookie = callback(t, rpClient, authorizeResp)

	// verify new session created
	sess = sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, sess.StatusCode)
	assert.NotEqual(t, initialSessionCookie.Value, sessionCookie.Value)
}

func TestCallback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)
}

func TestCallback_SessionStateRequired(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.OpenIDConfig.TestProvider.WithCheckSessionIFrameSupport(idp.ProviderServer.URL + "/checksession")
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	resp := authorize(t, rpClient, idp)

	// Get callback URL after successful auth
	params := resp.Location.Query()
	sessionState := params.Get("session_state")
	assert.NotEmpty(t, sessionState)

	callback(t, rpClient, resp)
}

func TestLogout(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)
	selfInitiatedLogout(t, rpClient, idp)
}

func TestLogoutLocal(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	localLogout(t, rpClient, idp)
}

func TestLogoutCallback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)
	logout(t, rpClient, idp)
}

func TestLogoutCallback_WithRedirect(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	redirect := idp.RelyingPartyServer.URL + "/api/me"

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)
	logout(t, rpClient, idp, redirect)
}

func TestFrontChannelLogout(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.OpenIDConfig.TestProvider.WithFrontChannelLogoutSupport()
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	sessionCookie := login(t, rpClient, idp)

	// Trigger front-channel logout
	sid := func(r *http.Request) string {
		r.AddCookie(sessionCookie)

		data, err := idp.RelyingPartyHandler.SessionManager.Get(r)
		assert.NoError(t, err)

		return data.ExternalSessionID()
	}

	frontchannelLogoutURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/logout/frontchannel")
	assert.NoError(t, err)

	req := idp.GetRequest(frontchannelLogoutURL.String())

	values := url.Values{}
	values.Add("sid", sid(req))
	values.Add("iss", idp.OpenIDConfig.Provider().Issuer())
	frontchannelLogoutURL.RawQuery = values.Encode()

	resp := get(t, rpClient, frontchannelLogoutURL.String())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSessionRefresh(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Second
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	// get initial session info
	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerboseWithRefresh
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	// wait until refresh cooldown has reached zero before refresh
	waitForRefreshCooldownTimer(t, idp, rpClient)

	resp = sessionRefresh(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var refreshedData session.MetadataVerboseWithRefresh
	err = json.Unmarshal([]byte(resp.Body), &refreshedData)
	assert.NoError(t, err)

	// session create and end times should be unchanged
	assert.WithinDuration(t, data.Session.CreatedAt, refreshedData.Session.CreatedAt, 0)
	assert.WithinDuration(t, data.Session.EndsAt, refreshedData.Session.EndsAt, 0)

	// token expiration and refresh times should be later than before
	assert.True(t, refreshedData.Tokens.ExpireAt.After(data.Tokens.ExpireAt))
	assert.True(t, refreshedData.Tokens.RefreshedAt.After(data.Tokens.RefreshedAt))

	allowedSkew := 5 * time.Second
	assert.WithinDuration(t, time.Now().Add(idp.ProviderHandler.TokenDuration), refreshedData.Tokens.ExpireAt, allowedSkew)
	assert.WithinDuration(t, time.Now(), refreshedData.Tokens.RefreshedAt, allowedSkew)

	sessionEndDuration := time.Duration(refreshedData.Session.EndsInSeconds) * time.Second
	// 1 second < time until session ends <= configured max session lifetime
	assert.LessOrEqual(t, sessionEndDuration, cfg.Session.MaxLifetime)
	assert.Greater(t, sessionEndDuration, time.Second)

	tokenExpiryDuration := time.Duration(refreshedData.Tokens.ExpireInSeconds) * time.Second
	// 1 second < time until token expires <= max duration for tokens from IDP
	assert.LessOrEqual(t, tokenExpiryDuration, idp.ProviderHandler.TokenDuration)
	assert.Greater(t, tokenExpiryDuration, time.Second)

	// auto refresh is not enabled
	assert.Less(t, refreshedData.Tokens.NextAutoRefreshInSeconds, refreshedData.Tokens.ExpireInSeconds)
	assert.Equal(t, refreshedData.Tokens.NextAutoRefreshInSeconds, int64(-1))

	assert.True(t, refreshedData.Tokens.RefreshCooldown)
	// 1 second < refresh cooldown <= minimum refresh interval
	assert.LessOrEqual(t, refreshedData.Tokens.RefreshCooldownSeconds, session.RefreshMinInterval)
	assert.Greater(t, refreshedData.Tokens.RefreshCooldownSeconds, int64(1))

	assert.True(t, data.Session.Active)
	assert.True(t, refreshedData.Session.Active)

	assert.True(t, data.Session.TimeoutAt.IsZero())
	assert.True(t, refreshedData.Session.TimeoutAt.IsZero())

	assert.Equal(t, int64(-1), data.Session.TimeoutInSeconds)
	assert.Equal(t, int64(-1), refreshedData.Session.TimeoutInSeconds)
}

func TestSessionRefresh_Disabled(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = false

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Second
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionRefresh(t, idp, rpClient)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSessionRefresh_WithInactivity(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true
	cfg.Session.Inactivity = true
	cfg.Session.InactivityTimeout = 10 * time.Minute

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Second
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	// get initial session info
	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerboseWithRefresh
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	// wait until refresh cooldown has reached zero before refresh
	waitForRefreshCooldownTimer(t, idp, rpClient)

	resp = sessionRefresh(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var refreshedData session.MetadataVerboseWithRefresh
	err = json.Unmarshal([]byte(resp.Body), &refreshedData)
	assert.NoError(t, err)

	maxDelta := 5 * time.Second

	assert.True(t, data.Session.Active)
	assert.True(t, refreshedData.Session.Active)

	assert.False(t, data.Session.TimeoutAt.IsZero())
	assert.False(t, refreshedData.Session.TimeoutAt.IsZero())

	expectedTimeoutAt := time.Now().Add(cfg.Session.InactivityTimeout)
	assert.WithinDuration(t, expectedTimeoutAt, data.Session.TimeoutAt, maxDelta)
	assert.WithinDuration(t, expectedTimeoutAt, refreshedData.Session.TimeoutAt, maxDelta)

	assert.True(t, refreshedData.Session.TimeoutAt.After(data.Session.TimeoutAt))

	previousTimeoutDuration := time.Duration(data.Session.TimeoutInSeconds) * time.Second
	assert.WithinDuration(t, expectedTimeoutAt, time.Now().Add(previousTimeoutDuration), maxDelta)

	refreshedTimeoutDuration := time.Duration(refreshedData.Session.TimeoutInSeconds) * time.Second
	assert.WithinDuration(t, expectedTimeoutAt, time.Now().Add(refreshedTimeoutDuration), maxDelta)
}

func TestSessionRefresh_WithRefreshAuto(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true
	cfg.Session.RefreshAuto = true

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Second
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	// get initial session info
	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerboseWithRefresh
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	// wait until refresh cooldown has reached zero before refresh
	waitForRefreshCooldownTimer(t, idp, rpClient)

	resp = sessionRefresh(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var refreshedData session.MetadataVerboseWithRefresh
	err = json.Unmarshal([]byte(resp.Body), &refreshedData)
	assert.NoError(t, err)

	// 1 second < next token refresh <= seconds until token expires
	assert.LessOrEqual(t, refreshedData.Tokens.NextAutoRefreshInSeconds, refreshedData.Tokens.ExpireInSeconds)
	assert.Greater(t, refreshedData.Tokens.NextAutoRefreshInSeconds, int64(1))
}

func TestSession(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Minute
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerbose
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	allowedSkew := 5 * time.Second
	assert.WithinDuration(t, time.Now(), data.Session.CreatedAt, allowedSkew)
	assert.WithinDuration(t, time.Now().Add(cfg.Session.MaxLifetime), data.Session.EndsAt, allowedSkew)
	assert.WithinDuration(t, time.Now().Add(idp.ProviderHandler.TokenDuration), data.Tokens.ExpireAt, allowedSkew)
	assert.WithinDuration(t, time.Now(), data.Tokens.RefreshedAt, allowedSkew)

	sessionEndDuration := time.Duration(data.Session.EndsInSeconds) * time.Second
	// 1 second < time until session ends <= configured max session lifetime
	assert.LessOrEqual(t, sessionEndDuration, cfg.Session.MaxLifetime)
	assert.Greater(t, sessionEndDuration, time.Second)

	tokenExpiryDuration := time.Duration(data.Tokens.ExpireInSeconds) * time.Second
	// 1 second < time until token expires <= max duration for tokens from IDP
	assert.LessOrEqual(t, tokenExpiryDuration, idp.ProviderHandler.TokenDuration)
	assert.Greater(t, tokenExpiryDuration, time.Second)

	assert.True(t, data.Session.Active)
	assert.True(t, data.Session.TimeoutAt.IsZero())
	assert.Equal(t, int64(-1), data.Session.TimeoutInSeconds)
}

func TestSession_WithInactivity(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true
	cfg.Session.Inactivity = true
	cfg.Session.InactivityTimeout = 10 * time.Minute

	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerbose
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	maxDelta := 5 * time.Second

	assert.True(t, data.Session.Active)
	assert.False(t, data.Session.TimeoutAt.IsZero())

	expectedTimeoutAt := time.Now().Add(cfg.Session.InactivityTimeout)
	assert.WithinDuration(t, expectedTimeoutAt, data.Session.TimeoutAt, maxDelta)

	actualTimeoutDuration := time.Duration(data.Session.TimeoutInSeconds) * time.Second
	assert.WithinDuration(t, expectedTimeoutAt, time.Now().Add(actualTimeoutDuration), maxDelta)
}

func TestSession_WithRefresh(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Minute
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerboseWithRefresh
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	allowedSkew := 5 * time.Second
	assert.WithinDuration(t, time.Now(), data.Session.CreatedAt, allowedSkew)
	assert.WithinDuration(t, time.Now().Add(cfg.Session.MaxLifetime), data.Session.EndsAt, allowedSkew)
	assert.WithinDuration(t, time.Now().Add(idp.ProviderHandler.TokenDuration), data.Tokens.ExpireAt, allowedSkew)
	assert.WithinDuration(t, time.Now(), data.Tokens.RefreshedAt, allowedSkew)

	sessionEndDuration := time.Duration(data.Session.EndsInSeconds) * time.Second
	// 1 second < time until session ends <= configured max session lifetime
	assert.LessOrEqual(t, sessionEndDuration, cfg.Session.MaxLifetime)
	assert.Greater(t, sessionEndDuration, time.Second)

	tokenExpiryDuration := time.Duration(data.Tokens.ExpireInSeconds) * time.Second
	// 1 second < time until token expires <= max duration for tokens from IDP
	assert.LessOrEqual(t, tokenExpiryDuration, idp.ProviderHandler.TokenDuration)
	assert.Greater(t, tokenExpiryDuration, time.Second)

	// auto refresh is not enabled
	assert.Less(t, data.Tokens.NextAutoRefreshInSeconds, data.Tokens.ExpireInSeconds)
	assert.Equal(t, data.Tokens.NextAutoRefreshInSeconds, int64(-1))

	assert.True(t, data.Tokens.RefreshCooldown)
	// 1 second < refresh cooldown <= minimum refresh interval
	assert.LessOrEqual(t, data.Tokens.RefreshCooldownSeconds, session.RefreshMinInterval)
	assert.Greater(t, data.Tokens.RefreshCooldownSeconds, int64(1))

	assert.True(t, data.Session.Active)
	assert.True(t, data.Session.TimeoutAt.IsZero())
	assert.Equal(t, int64(-1), data.Session.TimeoutInSeconds)
}

func TestSession_WithRefreshAuto(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true
	cfg.Session.RefreshAuto = true

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Minute
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerboseWithRefresh
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	// 1 second < next token refresh <= seconds until token expires
	assert.LessOrEqual(t, data.Tokens.NextAutoRefreshInSeconds, data.Tokens.ExpireInSeconds)
	assert.Greater(t, data.Tokens.NextAutoRefreshInSeconds, int64(1))
}

func TestPing(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	resp := get(t, rpClient, idp.RelyingPartyServer.URL+"/oauth2/ping")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "pong", resp.Body)
}

func localLogin(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) response {
	// First, run /oauth2/login to set cookies
	loginURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/login")
	assert.NoError(t, err)

	resp := get(t, rpClient, loginURL.String())
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(loginURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)
	loginCookie := getCookieFromJar(cookie.Login, cookies)

	assert.Nil(t, sessionCookie)
	assert.NotNil(t, loginCookie)

	return resp
}

func authorize(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) response {
	resp := localLogin(t, rpClient, idp)

	// Follow redirect to authorize with identity provider
	resp = get(t, rpClient, resp.Location.String())
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	return resp
}

func callback(t *testing.T, rpClient *http.Client, authorizeResponse response) *http.Cookie {
	// Get callback URL after successful auth
	callbackURL := authorizeResponse.Location

	// Follow redirect to callback
	resp := get(t, rpClient, callbackURL.String())
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(callbackURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)
	loginCookie := getCookieFromJar(cookie.Login, cookies)

	assert.NotNil(t, sessionCookie)
	assert.Nil(t, loginCookie)

	return sessionCookie
}

func login(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) *http.Cookie {
	resp := authorize(t, rpClient, idp)
	return callback(t, rpClient, resp)
}

func selfInitiatedLogout(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider, redirectAfterLogout ...string) response {
	// Request self-initiated logout
	logoutURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/logout")
	assert.NoError(t, err)

	if len(redirectAfterLogout) > 0 {
		v := url.Values{}
		v.Set(urlpkg.RedirectQueryParameter, redirectAfterLogout[0])
		logoutURL.RawQuery = v.Encode()
	}

	resp := get(t, rpClient, logoutURL.String())
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(logoutURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)

	// Get endsession endpoint after local logout
	endsessionURL := resp.Location

	idpserverURL, err := url.Parse(idp.ProviderServer.URL)
	assert.NoError(t, err)

	req := idp.GetRequest(idp.RelyingPartyServer.URL + "/oauth2/logout")
	expectedLogoutCallbackURL, err := urlpkg.LogoutCallback(req)
	assert.NoError(t, err)

	endsessionParams := endsessionURL.Query()
	assert.Equal(t, idpserverURL.Host, endsessionURL.Host)
	assert.Equal(t, "/endsession", endsessionURL.Path)
	assert.Equal(t, expectedLogoutCallbackURL, endsessionParams.Get("post_logout_redirect_uri"))
	assert.NotEmpty(t, endsessionParams.Get("id_token_hint"))
	assert.NotEmpty(t, endsessionParams.Get("state"))

	return resp
}

func logout(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider, redirectAfterLogout ...string) {
	// Get endsession endpoint after local logout
	resp := selfInitiatedLogout(t, rpClient, idp, redirectAfterLogout...)
	expectedState := resp.Location.Query().Get("state")

	// Follow redirect to endsession endpoint at identity provider
	resp = get(t, rpClient, resp.Location.String())
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	logoutCallbackURI := resp.Location

	// Assert state for callback equals state sent in initial logout request
	actualState := logoutCallbackURI.Query().Get("state")
	assert.NotEmpty(t, actualState)
	assert.Equal(t, expectedState, actualState)

	// Assert post-logout redirect URI after successful logout at identity provider
	req := idp.GetRequest(idp.RelyingPartyServer.URL + "/oauth2/logout")
	expectedLogoutCallbackURL, err := urlpkg.LogoutCallback(req)
	assert.NoError(t, err)

	assert.Contains(t, logoutCallbackURI.String(), expectedLogoutCallbackURL)
	assert.Equal(t, "/oauth2/logout/callback", logoutCallbackURI.Path)

	// Follow redirect back to logout callback
	resp = get(t, rpClient, logoutCallbackURI.String())

	// Get post-logout redirect URI after redirect back to logout callback
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	expectedRedirect := "https://google.com"
	if len(redirectAfterLogout) > 0 {
		expectedRedirect = redirectAfterLogout[0]
	}
	assert.Equal(t, expectedRedirect, resp.Location.String())

	cookies := rpClient.Jar.Cookies(logoutCallbackURI)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)
}

func localLogout(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) response {
	logoutURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/logout/local")
	assert.NoError(t, err)

	resp := get(t, rpClient, logoutURL.String())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(logoutURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)

	return resp
}

func sessionInfo(t *testing.T, idp *mock.IdentityProvider, rpClient *http.Client) response {
	sessionInfoURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/session")
	assert.NoError(t, err)

	return get(t, rpClient, sessionInfoURL.String())
}

func sessionRefresh(t *testing.T, idp *mock.IdentityProvider, rpClient *http.Client) response {
	sessionRefreshURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/session/refresh")
	assert.NoError(t, err)

	return post(t, rpClient, sessionRefreshURL.String())
}

func waitForRefreshCooldownTimer(t *testing.T, idp *mock.IdentityProvider, rpClient *http.Client) {
	timeout := time.After(5 * time.Second)
	ticker := time.Tick(500 * time.Millisecond)
	for {
		select {
		case <-timeout:
			assert.Fail(t, "refresh cooldown timer exceeded timeout")
		case <-ticker:
			resp := sessionInfo(t, idp, rpClient)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var temp session.MetadataVerboseWithRefresh
			err := json.Unmarshal([]byte(resp.Body), &temp)
			assert.NoError(t, err)

			if !temp.Tokens.RefreshCooldown {
				return
			}
		}
	}
}

type response struct {
	Body       string
	Location   *url.URL
	StatusCode int
}

type header struct {
	key, value string
}

func get(t *testing.T, client *http.Client, url string, headers ...header) response {
	return request(t, client, http.MethodGet, url, headers...)
}

func post(t *testing.T, client *http.Client, url string) response {
	return request(t, client, http.MethodPost, url)
}

func request(t *testing.T, client *http.Client, method, url string, headers ...header) response {
	req, err := http.NewRequest(method, url, nil)
	assert.NoError(t, err)

	for _, h := range headers {
		req.Header.Add(h.key, h.value)
	}

	resp, err := client.Do(req)
	assert.NoError(t, err)

	location, err := resp.Location()
	if !errors.Is(err, http.ErrNoLocation) {
		assert.NoError(t, err)
	}

	return response{
		Body:       body(t, resp),
		Location:   location,
		StatusCode: resp.StatusCode,
	}
}

func body(t *testing.T, resp *http.Response) string {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	return string(body)
}

type upstream struct {
	Server          *httptest.Server
	URL             *url.URL
	idp             *mock.IdentityProvider
	reverseProxyURL *url.URL
	requestCallback func(r *http.Request)
}

func (u *upstream) SetIdentityProvider(idp *mock.IdentityProvider) {
	u.idp = idp
	u.setReverseProxyUrl(idp.RelyingPartyServer.URL)
}

func (u *upstream) setReverseProxyUrl(raw string) {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	u.reverseProxyURL = parsed
}

func (u *upstream) hasValidToken(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if len(token) <= 0 {
		return false
	}

	jwks, err := u.idp.ProviderHandler.Provider.GetPublicJwkSet(r.Context())
	if err != nil {
		panic(err)
	}

	opts := []jwt.ParseOption{
		jwt.WithValidate(true),
		jwt.WithKeySet(*jwks),
		jwt.WithIssuer(u.idp.OpenIDConfig.Provider().Issuer()),
		jwt.WithAudience(u.idp.OpenIDConfig.Client().ClientID()),
	}

	_, err = jwt.ParseString(token, opts...)
	return err == nil
}

func newUpstream(t *testing.T) *upstream {
	u := new(upstream)
	u.requestCallback = func(r *http.Request) {}

	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.requestCallback(r)

		// Host should match the original authority from the ingress used to reach Wonderwall
		assert.Equal(t, u.reverseProxyURL.Host, r.Host)
		assert.NotEqual(t, u.URL.Host, r.Host)

		if u.hasValidToken(r) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("not ok"))
		}
	})
	server := httptest.NewServer(upstreamHandler)

	upstreamURL, err := url.Parse(server.URL)
	assert.NoError(t, err)

	u.Server = server
	u.URL = upstreamURL
	return u
}

func getCookieFromJar(name string, cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}

	return nil
}
