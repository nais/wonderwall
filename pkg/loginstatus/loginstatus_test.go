package loginstatus_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/loginstatus"
)

var cookieOpts = cookie.DefaultOptions().WithPath("/some/path")

func TestClient_ExchangeToken(t *testing.T) {
	server := httptest.NewServer(loginstatusHandler())
	httpclient := server.Client()

	cfg := newCfg(server.URL)
	client := loginstatus.NewClient(cfg, httpclient)

	for _, test := range []struct {
		token *jwt.AccessToken
		err   error
	}{
		{
			token: jwt.NewAccessToken("valid-token", nil),
		},
		{
			token: jwt.NewAccessToken("invalid-token", nil),
			err:   fmt.Errorf("client error: HTTP: %d: %s: %s", http.StatusUnauthorized, "access_denied", "No new and shiny token for you!"),
		},
		{
			token: jwt.NewAccessToken("internal-server-error", nil),
			err:   fmt.Errorf("server error: HTTP: %d: %s", http.StatusInternalServerError, "Oh no, it broke"),
		},
	} {
		response, err := client.ExchangeToken(context.Background(), test.token)
		if test.err != nil {
			assert.Error(t, test.err)
			assert.Nil(t, response)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, "new-and-shiny-token", response.AccessToken)
			assert.Equal(t, 3599, response.ExpiresIn)
		}
	}
}

func TestClient_SetCookie(t *testing.T) {
	tokenResponse := &loginstatus.TokenResponse{
		AccessToken: "some-token",
		ExpiresIn:   3599,
	}
	cfg := newCfg("https://some-server")

	client := loginstatus.NewClient(cfg, http.DefaultClient)
	opts := client.CookieOptions(cookieOpts)

	writer := httptest.NewRecorder()
	client.SetCookie(writer, tokenResponse, opts)

	cookies := writer.Result().Cookies()

	var result *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.CookieName {
			result = c
		}
	}

	expectedExpires := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	assert.NotNil(t, result)
	assert.Equal(t, cfg.CookieDomain, result.Domain)
	assert.True(t, result.Expires.Before(expectedExpires))
	assert.Equal(t, cfg.CookieName, result.Name)
	assert.Equal(t, tokenResponse.AccessToken, result.Value)
	assert.True(t, result.HttpOnly)
	assert.Equal(t, http.SameSite(0), result.SameSite)
	assert.Equal(t, opts.Secure, result.Secure)
	assert.Equal(t, "/", result.Path)
}

func TestClient_ClearCookie(t *testing.T) {
	cfg := newCfg("https://some-server")
	client := loginstatus.NewClient(cfg, http.DefaultClient)
	opts := client.CookieOptions(cookieOpts)

	writer := httptest.NewRecorder()
	client.ClearCookie(writer, opts)

	cookies := writer.Result().Cookies()

	var result *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.CookieName {
			result = c
		}
	}

	assert.NotNil(t, result)
	assert.Equal(t, cfg.CookieDomain, result.Domain)
	assert.Equal(t, cfg.CookieName, result.Name)
	assert.True(t, result.Expires.Before(time.Now()))
	assert.True(t, result.Expires.Equal(time.Unix(0, 0)))
	assert.Equal(t, -1, result.MaxAge)
	assert.True(t, result.HttpOnly)
	assert.Equal(t, "", result.Value)
	assert.Equal(t, http.SameSite(0), result.SameSite)
	assert.Equal(t, opts.Secure, result.Secure)
	assert.Equal(t, "/", result.Path)
}

func TestClient_HasCookie(t *testing.T) {
	cfg := newCfg("https://some-server")
	client := loginstatus.NewClient(cfg, http.DefaultClient)
	opts := client.CookieOptions(cookieOpts)

	c := cookie.Make(cfg.CookieName, "some-value", opts)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(c.Cookie)

	actual := client.HasCookie(r)
	assert.True(t, actual)

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	actual = client.HasCookie(r)
	assert.False(t, actual)
}

func TestClient_CookieOptions(t *testing.T) {
	cfg := newCfg("https://some-server")
	client := loginstatus.NewClient(cfg, http.DefaultClient)

	for _, test := range []struct {
		name string
		opts cookie.Options
	}{
		{
			name: "default cookie options",
			opts: cookie.DefaultOptions(),
		},
		{
			name: "override domain",
			opts: cookie.DefaultOptions().WithDomain(".some.other.domain"),
		},
		{
			name: "override path",
			opts: cookie.DefaultOptions().WithPath("/some/path"),
		},
		{
			name: "override samesite",
			opts: cookie.DefaultOptions().WithSameSite(http.SameSiteStrictMode),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := client.CookieOptions(test.opts)

			assert.Empty(t, opts.ExpiresIn)
			assert.True(t, opts.Secure)

			// options below should never be overridden regardless of input
			assert.Equal(t, cfg.CookieDomain, opts.Domain)
			assert.Equal(t, "/", opts.Path)
			assert.Equal(t, http.SameSiteDefaultMode, opts.SameSite)
		})
	}
}

func newCfg(serverURL string) config.Loginstatus {
	return config.Loginstatus{
		Enabled:           true,
		CookieDomain:      "some.domain",
		CookieName:        "some-cookie",
		ResourceIndicator: "https://loginstatus",
		TokenURL:          fmt.Sprintf("%s/token", serverURL),
	}
}

func loginstatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")

		switch {
		// access_token is valid
		case r.URL.Path == "/token" && token == "valid-token":
			response := `{ "access_token": "new-and-shiny-token", "expires_in": 3599 }`
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		// access_token is invalid
		case r.URL.Path == "/token":
			response := `{ "error": "access_denied", "error_description": "No new and shiny token for you!" }`
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(response))
		// internal server error
		case r.URL.Path == "/token" && token == "internal-server-error":
			response := `Oh no, it broke`
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(response))
		}
	}
}
