package handler_test

import (
	"encoding/base64"
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

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cookie"
	urlpkg "github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/session"
)

func TestHandler_Login(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()

	resp := localLogin(t, rpClient, idp)
	loginURL := resp.Location

	req := idp.GetRequest(idp.RelyingPartyServer.URL + "/oauth2/login")

	expectedCallbackURL, err := urlpkg.LoginCallbackURL(req)
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
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	callbackURL := resp.Location
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

	// Get endsession endpoint after local logout
	endsessionURL := resp.Location

	idpserverURL, err := url.Parse(idp.ProviderServer.URL)
	assert.NoError(t, err)

	req := idp.GetRequest(idp.RelyingPartyServer.URL + "/oauth2/logout")
	expectedLogoutCallbackURL, err := urlpkg.LogoutCallbackURL(req)
	assert.NoError(t, err)

	endsessionParams := endsessionURL.Query()
	assert.Equal(t, idpserverURL.Host, endsessionURL.Host)
	assert.Equal(t, "/endsession", endsessionURL.Path)
	assert.Equal(t, []string{expectedLogoutCallbackURL}, endsessionParams["post_logout_redirect_uri"])
	assert.NotEmpty(t, endsessionParams["id_token_hint"])
}

func TestHandler_LogoutCallback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)
	logout(t, rpClient, idp)
}

func TestHandler_FrontChannelLogout(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	idp.OpenIDConfig.TestProvider.WithFrontChannelLogoutSupport()
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	sessionCookie := login(t, rpClient, idp)

	// Trigger front-channel logout
	sid := func(r *http.Request) string {
		ciphertext, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
		assert.NoError(t, err)

		sessionKey, err := idp.RelyingPartyHandler.GetCrypter().Decrypt(ciphertext)
		assert.NoError(t, err)

		data, err := idp.RelyingPartyHandler.GetSessions().GetForKey(r, string(sessionKey))
		assert.NoError(t, err)

		return data.ExternalSessionID
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

func TestHandler_SessionStateRequired(t *testing.T) {
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
}

func TestHandler_SessionInfo(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true

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
}

func TestHandler_SessionInfo_WithRefresh(t *testing.T) {
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

	// 1 second < next token refresh <= seconds until token expires
	assert.LessOrEqual(t, data.Tokens.NextAutoRefreshInSeconds, data.Tokens.ExpireInSeconds)
	assert.Greater(t, data.Tokens.NextAutoRefreshInSeconds, int64(1))

	assert.True(t, data.Tokens.RefreshCooldown)
	// 1 second < refresh cooldown <= minimum refresh interval
	assert.LessOrEqual(t, data.Tokens.RefreshCooldownSeconds, session.RefreshMinInterval)
	assert.Greater(t, data.Tokens.RefreshCooldownSeconds, int64(1))
}

func TestHandler_SessionRefresh(t *testing.T) {
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
	func() {
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
				err = json.Unmarshal([]byte(resp.Body), &temp)
				assert.NoError(t, err)

				if !temp.Tokens.RefreshCooldown {
					return
				}
			}
		}
	}()

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

	// 1 second < next token refresh <= seconds until token expires
	assert.LessOrEqual(t, refreshedData.Tokens.NextAutoRefreshInSeconds, refreshedData.Tokens.ExpireInSeconds)
	assert.Greater(t, refreshedData.Tokens.NextAutoRefreshInSeconds, int64(1))

	assert.True(t, refreshedData.Tokens.RefreshCooldown)
	// 1 second < refresh cooldown <= minimum refresh interval
	assert.LessOrEqual(t, refreshedData.Tokens.RefreshCooldownSeconds, session.RefreshMinInterval)
	assert.Greater(t, refreshedData.Tokens.RefreshCooldownSeconds, int64(1))
}

func TestHandler_SessionRefresh_Disabled(t *testing.T) {
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

func TestHandler_Default(t *testing.T) {
	up := newUpstream(t)
	defer up.Server.Close()

	t.Run("without auto-login", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetReverseProxyUrl(idp.RelyingPartyServer.URL)
		rpClient := idp.RelyingPartyClient()

		// initial request without session
		resp := get(t, rpClient, idp.RelyingPartyServer.URL)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "not ok", resp.Body)

		// acquire session
		login(t, rpClient, idp)

		// retry request with session
		resp = get(t, rpClient, idp.RelyingPartyServer.URL)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "ok", resp.Body)
	})

	t.Run("with auto-login", func(t *testing.T) {
		cfg := mock.Config()
		cfg.AutoLogin = true
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetReverseProxyUrl(idp.RelyingPartyServer.URL)
		rpClient := idp.RelyingPartyClient()

		// initial request without session
		target := idp.RelyingPartyServer.URL + "/"

		resp := get(t, rpClient, target)
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// redirect should point to local login endpoint
		loginLocation := resp.Location
		assert.Equal(t, idp.RelyingPartyServer.URL+"/oauth2/login?redirect-encoded="+urlpkg.RedirectEncoded("/"), loginLocation.String())

		// follow redirect to local login endpoint
		resp = get(t, rpClient, loginLocation.String())
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// redirect should point to identity provider
		authorizeLocation := resp.Location

		authorizeEndpoint := *authorizeLocation
		authorizeEndpoint.RawQuery = ""
		assert.Equal(t, idp.OpenIDConfig.Provider().AuthorizationEndpoint(), authorizeEndpoint.String())

		// follow redirect to identity provider for login
		resp = get(t, rpClient, authorizeLocation.String())
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// redirect should point back to relying party
		callbackLocation := resp.Location

		callbackEndpoint := *callbackLocation
		callbackEndpoint.RawQuery = ""

		req := idp.GetRequest(callbackLocation.String())
		expectedCallbackURL, err := urlpkg.LoginCallbackURL(req)
		assert.NoError(t, err)
		assert.Equal(t, expectedCallbackURL, callbackEndpoint.String())

		// follow redirect back to relying party
		resp = get(t, rpClient, callbackLocation.String())
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// finally, follow redirect back to original target, now with a session
		targetLocation := resp.Location
		assert.Equal(t, target, targetLocation.String())

		resp = get(t, rpClient, targetLocation.String())
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "ok", resp.Body)
	})

	t.Run("with auto-login for non-GET requests", func(t *testing.T) {
		for _, method := range []string{
			http.MethodConnect,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
			http.MethodPatch,
			http.MethodPost,
			http.MethodPut,
			http.MethodTrace,
		} {
			t.Run(method, func(t *testing.T) {
				cfg := mock.Config()
				cfg.AutoLogin = true
				cfg.UpstreamHost = up.URL.Host
				idp := mock.NewIdentityProvider(cfg)
				defer idp.Close()

				up.SetReverseProxyUrl(idp.RelyingPartyServer.URL)
				rpClient := idp.RelyingPartyClient()

				req, err := http.NewRequest(method, idp.RelyingPartyServer.URL, nil)
				assert.NoError(t, err)

				resp, err := rpClient.Do(req)
				assert.NoError(t, err)
				defer resp.Body.Close()

				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			})
		}
	})

	t.Run("with auto-login and ignored paths", func(t *testing.T) {
		for pattern, tt := range map[string]struct {
			match    []string
			nonMatch []string
		}{
			"/": {
				match: []string{
					"/",
					"",
				},
				nonMatch: []string{
					"/a",
					"/a/b",
				},
			},
			"/exact/match": {
				match: []string{
					"/exact/match",
					"/exact/match/",
				},
				nonMatch: []string{
					"/exact/match/huh",
				},
			},
			"/allowed": {
				match: []string{
					"/allowed",
					"/allowed/",
				},
				nonMatch: []string{
					"/allowe",
					"/allowed/no",
					"/not-allowed",
					"/not-allowed/allowed",
				},
			},
			"/wildcard/*": {
				match: []string{
					"/wildcard/very",
					"/wildcard/very/",
				},
				nonMatch: []string{
					"/wildcard",
					"/wildcard/",
					"/wildcard/yup/nope",
				},
			},
			"/deeper/*/*": {
				match: []string{
					"/deeper/1/2",
					"/deeper/1/2/",
				},
				nonMatch: []string{
					"/deeper",
					"/deeper/",
					"/deeper/1",
					"/deeper/1/",
					"/deeper/1/2/3",
				},
			},
			"/any*": {
				match: []string{
					"/any",
					"/any/",
					"/anything",
					"/anything/",
					"/anywho",
					"/anywho/",
				},
				nonMatch: []string{
					"/any/thing",
					"/any/thing/",
					"/anywho/mst/ve",
				},
			},
			"/trailing/": {
				match: []string{
					"/trailing",
					"/trailing/",
				},
				nonMatch: []string{
					"/trailing/path",
					"/trailing/path/",
				},
			},
		} {
			t.Run(pattern, func(t *testing.T) {
				cfg := mock.Config()
				cfg.UpstreamHost = up.URL.Host
				cfg.AutoLogin = true
				cfg.AutoLoginIgnorePaths = []string{pattern}

				idp := mock.NewIdentityProvider(cfg)
				defer idp.Close()
				up.SetReverseProxyUrl(idp.RelyingPartyServer.URL)
				rpClient := idp.RelyingPartyClient()

				t.Run("match", func(t *testing.T) {
					for _, path := range tt.match {
						t.Run(path, func(t *testing.T) {
							target := idp.RelyingPartyServer.URL + path
							resp := get(t, rpClient, target)

							assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
							assert.Equal(t, "not ok", resp.Body)
						})
					}
				})

				t.Run("non-match", func(t *testing.T) {
					for _, path := range tt.nonMatch {
						t.Run(path, func(t *testing.T) {
							target := idp.RelyingPartyServer.URL + path
							resp := get(t, rpClient, target)

							assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
						})
					}
				})
			})
		}
	})
}

func localLogin(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) response {
	// First, run /oauth2/login to set cookies
	loginURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/login")
	assert.NoError(t, err)

	resp := get(t, rpClient, loginURL.String())
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

func authorize(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) response {
	resp := localLogin(t, rpClient, idp)

	// Follow redirect to authorize with identity provider
	resp = get(t, rpClient, resp.Location.String())
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	return resp
}

func callback(t *testing.T, rpClient *http.Client, authorizeResponse response) *http.Cookie {
	// Get callback URL after successful auth
	callbackURL := authorizeResponse.Location

	// Follow redirect to callback
	resp := get(t, rpClient, callbackURL.String())
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

func login(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) *http.Cookie {
	resp := authorize(t, rpClient, idp)
	return callback(t, rpClient, resp)
}

func localLogout(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) response {
	// Request self-initiated logout
	logoutURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/logout")
	assert.NoError(t, err)

	resp := get(t, rpClient, logoutURL.String())
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	cookies := rpClient.Jar.Cookies(logoutURL)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)

	return resp
}

func logout(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) {
	// Get endsession endpoint after local logout
	resp := localLogout(t, rpClient, idp)

	// Follow redirect to endsession endpoint at identity provider
	resp = get(t, rpClient, resp.Location.String())
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	// Get post-logout redirect URI after successful logout at identity provider
	logoutCallbackURI := resp.Location

	req := idp.GetRequest(resp.Location.String())
	expectedLogoutCallbackURL, err := urlpkg.LogoutCallbackURL(req)
	assert.NoError(t, err)

	assert.Contains(t, logoutCallbackURI.String(), expectedLogoutCallbackURL)
	assert.Equal(t, "/oauth2/logout/callback", logoutCallbackURI.Path)

	// Follow redirect back to logout callback
	resp = get(t, rpClient, logoutCallbackURI.String())
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	// Get post-logout redirect URI after redirect back to logout callback
	assert.Equal(t, "https://google.com", resp.Location.String())

	cookies := rpClient.Jar.Cookies(logoutCallbackURI)
	sessionCookie := getCookieFromJar(cookie.Session, cookies)

	assert.Nil(t, sessionCookie)
}

func sessionInfo(t *testing.T, idp *mock.IdentityProvider, rpClient *http.Client) response {
	sessionInfoURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/session")
	assert.NoError(t, err)

	return get(t, rpClient, sessionInfoURL.String())
}

func sessionRefresh(t *testing.T, idp *mock.IdentityProvider, rpClient *http.Client) response {
	sessionRefreshURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/session/refresh")
	assert.NoError(t, err)

	return get(t, rpClient, sessionRefreshURL.String())
}

type response struct {
	Body       string
	Location   *url.URL
	StatusCode int
}

func get(t *testing.T, client *http.Client, url string) response {
	resp, err := client.Get(url)
	assert.NoError(t, err)
	defer resp.Body.Close()

	location, err := resp.Location()
	if !errors.Is(http.ErrNoLocation, err) {
		assert.NoError(t, err)
	}

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	return response{
		Body:       string(body),
		Location:   location,
		StatusCode: resp.StatusCode,
	}
}

type upstream struct {
	Server          *httptest.Server
	URL             *url.URL
	reverseProxyURL *url.URL
}

func (u *upstream) SetReverseProxyUrl(raw string) {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	u.reverseProxyURL = parsed
}

func newUpstream(t *testing.T) *upstream {
	u := new(upstream)

	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Host should match the original authority from the ingress used to reach Wonderwall
		assert.Equal(t, u.reverseProxyURL.Host, r.Host)
		assert.NotEqual(t, u.URL.Host, r.Host)

		if len(token) > 0 {
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
