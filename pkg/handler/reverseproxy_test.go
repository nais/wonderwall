package handler_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	urlpkg "github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/mock"
)

func TestReverseProxy(t *testing.T) {
	up := newUpstream(t)
	defer up.Server.Close()

	t.Run("without auto-login", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
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

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		// initial request without session
		target := idp.RelyingPartyServer.URL + "/"

		resp := get(t, rpClient, target)
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// redirect should point to local login endpoint
		loginLocation := resp.Location
		assert.Equal(t, idp.RelyingPartyServer.URL+"/oauth2/login?redirect=%2F", loginLocation.String())

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

				up.SetIdentityProvider(idp)
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
			"/nested/**": {
				match: []string{
					"/nested",
					"/nested/",
					"/nested/very",
					"/nested/very/deep",
					"/nested/very/deep/deeper",
				},
				nonMatch: []string{
					"/not/nested",
					"/not/nested/very",
				},
			},
			"/static/**/*.js": {
				match: []string{
					"/static/bundle.js",
					"/static/min/bundle.js",
					"/static/vendor/min/bundle.js",
				},
				nonMatch: []string{
					"/static",
					"/static/",
					"/static/some.css",
					"/static/min",
					"/static/min/",
					"/static/min/some.css",
					"/static/vendor/min/some.css",
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

				up.SetIdentityProvider(idp)
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

	t.Run("request with authorization header set", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		t.Run("should be preserved if no session found", func(t *testing.T) {
			up.requestCallback = func(r *http.Request) {
				authorization := r.Header.Get("Authorization")
				assert.Equal(t, "Bearer some-authorization", authorization)
			}

			resp := getWithHeaders(t, rpClient, idp.RelyingPartyServer.URL, map[string]string{
				"Authorization": "Bearer some-authorization",
			})
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			assert.Equal(t, "not ok", resp.Body)
		})

		t.Run("should be overwritten if session found", func(t *testing.T) {
			// acquire session
			login(t, rpClient, idp)

			up.requestCallback = func(r *http.Request) {
				authorization := r.Header.Get("Authorization")
				assert.NotEqual(t, "Bearer some-authorization", authorization)
			}

			resp := getWithHeaders(t, rpClient, idp.RelyingPartyServer.URL, map[string]string{
				"Authorization": "Bearer some-authorization",
			})
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "ok", resp.Body)
		})
	})
}
