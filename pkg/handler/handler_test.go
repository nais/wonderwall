package handler_test

import (
	"encoding/json"
	"errors"
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

func selfInitiatedLogout(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) response {
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
	resp := selfInitiatedLogout(t, rpClient, idp)

	// Follow redirect to endsession endpoint at identity provider
	resp = get(t, rpClient, resp.Location.String())
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	// Get post-logout redirect URI after successful logout at identity provider
	logoutCallbackURI := resp.Location

	req := idp.GetRequest(resp.Location.String())
	expectedLogoutCallbackURL, err := urlpkg.LogoutCallback(req)
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

func localLogout(t *testing.T, rpClient *http.Client, idp *mock.IdentityProvider) response {
	logoutURL, err := url.Parse(idp.RelyingPartyServer.URL + "/oauth2/logout/local")
	assert.NoError(t, err)

	resp := get(t, rpClient, logoutURL.String())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

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

func get(t *testing.T, client *http.Client, url string) response {
	resp, err := client.Get(url)
	assert.NoError(t, err)

	location, err := resp.Location()
	if !errors.Is(http.ErrNoLocation, err) {
		assert.NoError(t, err)
	}

	return response{
		Body:       body(t, resp),
		Location:   location,
		StatusCode: resp.StatusCode,
	}
}

func getWithHeaders(t *testing.T, client *http.Client, url string, headers map[string]string) response {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	assert.NoError(t, err)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	assert.NoError(t, err)

	location, err := resp.Location()
	if !errors.Is(http.ErrNoLocation, err) {
		assert.NoError(t, err)
	}

	return response{
		Body:       body(t, resp),
		Location:   location,
		StatusCode: resp.StatusCode,
	}
}

func post(t *testing.T, client *http.Client, url string) response {
	req, err := http.NewRequest(http.MethodPost, url, nil)
	assert.NoError(t, err)

	resp, err := client.Do(req)
	assert.NoError(t, err)

	location, err := resp.Location()
	if !errors.Is(http.ErrNoLocation, err) {
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
