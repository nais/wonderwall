package handler_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

var navigateFetchHeaders = []header{
	{"Sec-Fetch-Mode", "navigate"},
	{"Sec-Fetch-Dest", "document"},
}

func TestReverseProxy(t *testing.T) {
	up := newUpstream(t)
	defer up.Server.Close()

	loginURL := func(idp *mock.IdentityProvider, target string) string {
		if target == "" {
			return idp.RelyingPartyServer.URL + "/oauth2/login"
		}
		return idp.RelyingPartyServer.URL + "/oauth2/login?redirect=" + url.QueryEscape(target)
	}

	// assert that autologin intercepts the request and redirects to the login endpoint
	assertAutoLoginRedirectResponse := func(t *testing.T, idp *mock.IdentityProvider, resp response, originalTarget string) {
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, loginURL(idp, originalTarget), resp.Location.String())
	}

	// assert that auto login intercepts the request and returns a 401 unauthorized
	assertAutoLoginUnauthorizedResponse := func(t *testing.T, idp *mock.IdentityProvider, resp response, originalReferer string) {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, loginURL(idp, originalReferer), resp.Location.String())
		assert.Equal(t, "unauthenticated, please log in", resp.Body)
	}

	// assert that the request is proxied to the upstream, which returns a 401 unauthorized
	assertUpstreamUnauthorizedResponse := func(t *testing.T, resp response) {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "not ok", resp.Body)
	}

	// assert that the request is proxied to the upstream, which returns a 200 ok
	assertUpstreamOKResponse := func(t *testing.T, resp response) {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "ok", resp.Body)
	}

	t.Run("without auto-login", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		// initial request without session
		resp := get(t, rpClient, idp.RelyingPartyServer.URL)
		assertUpstreamUnauthorizedResponse(t, resp)

		// acquire session
		login(t, rpClient, idp)

		// retry request with session
		resp = get(t, rpClient, idp.RelyingPartyServer.URL)
		assertUpstreamOKResponse(t, resp)
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

		resp := get(t, rpClient, target, navigateFetchHeaders...)
		assertAutoLoginRedirectResponse(t, idp, resp, "/")

		// follow redirect to local login endpoint
		resp = get(t, rpClient, resp.Location.String())
		assert.Equal(t, http.StatusFound, resp.StatusCode)

		// redirect should point to identity provider
		authorizeLocation := resp.Location
		authorizeEndpoint := *authorizeLocation
		authorizeEndpoint.RawQuery = ""
		assert.Equal(t, idp.OpenIDConfig.Provider().AuthorizationEndpoint(), authorizeEndpoint.String())

		// follow redirect to identity provider for login
		resp = get(t, rpClient, authorizeLocation.String())
		assert.Equal(t, http.StatusFound, resp.StatusCode)

		// redirect should point back to relying party
		callbackLocation := resp.Location
		callbackEndpoint := *callbackLocation
		callbackEndpoint.RawQuery = ""

		req := idp.GetRequest(callbackLocation.String())
		expectedCallbackURL, err := urlpkg.LoginCallback(req)
		assert.NoError(t, err)
		assert.Equal(t, expectedCallbackURL, callbackEndpoint.String())

		// follow redirect back to relying party
		resp = get(t, rpClient, callbackLocation.String())
		assert.Equal(t, http.StatusFound, resp.StatusCode)

		// finally, follow redirect back to original target, now with a session
		targetLocation := resp.Location
		assert.Equal(t, target, targetLocation.String())

		resp = get(t, rpClient, targetLocation.String())
		assertUpstreamOKResponse(t, resp)
	})

	t.Run("with auto-login for non-GET requests returns 401 unauthorized", func(t *testing.T) {
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

				resp := request(t, rpClient, method, idp.RelyingPartyServer.URL)

				if method == http.MethodHead {
					assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
					assert.Equal(t, loginURL(idp, ""), resp.Location.String())
					assert.Empty(t, resp.Body)
				} else {
					assertAutoLoginUnauthorizedResponse(t, idp, resp, "")
				}
			})
		}
	})

	t.Run("with auto-login for non-navigation requests returns 401 unauthorized", func(t *testing.T) {
		cfg := mock.Config()
		cfg.AutoLogin = true
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		target := idp.RelyingPartyServer.URL + "/"
		resp := get(t, rpClient, target)
		assertAutoLoginUnauthorizedResponse(t, idp, resp, "")

		referer := idp.RelyingPartyServer.URL + "/some-path"
		target = idp.RelyingPartyServer.URL + "/some-path/resource"
		resp = get(t, rpClient, target, header{"Referer", referer})
		assertAutoLoginUnauthorizedResponse(t, idp, resp, referer)
	})

	t.Run("with auto-login for navigation request without fetch metadata returns 3xx redirect", func(t *testing.T) {
		cfg := mock.Config()
		cfg.AutoLogin = true
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		target := idp.RelyingPartyServer.URL + "/some-path"

		for _, tt := range []struct {
			name    string
			headers []header
		}{
			{"happy path", []header{
				{"Accept", "text/html"},
			}},
			{"multiple values", []header{
				{"Accept", "application/xhtml+xml, application/xml, text/html"},
			}},
			{"multiple accept headers", []header{
				{"Accept", "application/xhtml+xml, application/xml;q=0.9"},
				{"Accept", "text/plain"},
				{"Accept", "text/html"},
			}},
			{"non-canonical value", []header{
				{"Accept", ", text/HTML "},
			}},
			{"with quality parameter", []header{
				{"Accept", "text/html;q=0.9"},
			}},
		} {
			t.Run(tt.name, func(t *testing.T) {
				noFetchMetadata := []header{
					{"Sec-Fetch-Mode", ""},
					{"Sec-Fetch-Dest", ""},
				}
				tt.headers = append(tt.headers, noFetchMetadata...)

				resp := get(t, rpClient, target, tt.headers...)
				assertAutoLoginRedirectResponse(t, idp, resp, "/some-path")
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
							resp := get(t, rpClient, target, navigateFetchHeaders...)
							assertUpstreamUnauthorizedResponse(t, resp)
						})
					}
				})

				t.Run("non-match", func(t *testing.T) {
					for _, path := range tt.nonMatch {
						t.Run(path, func(t *testing.T) {
							target := idp.RelyingPartyServer.URL + path
							resp := get(t, rpClient, target, navigateFetchHeaders...)
							assertAutoLoginRedirectResponse(t, idp, resp, path)
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

			resp := get(t, rpClient, idp.RelyingPartyServer.URL, header{"Authorization", "Bearer some-authorization"})
			assertUpstreamUnauthorizedResponse(t, resp)
		})

		t.Run("should be overwritten if session found", func(t *testing.T) {
			// acquire session
			login(t, rpClient, idp)

			up.requestCallback = func(r *http.Request) {
				authorization := r.Header.Get("Authorization")
				assert.NotEqual(t, "Bearer some-authorization", authorization)
			}

			resp := get(t, rpClient, idp.RelyingPartyServer.URL, header{"Authorization", "Bearer some-authorization"})
			assertUpstreamOKResponse(t, resp)
		})
	})

	t.Run("request with forwarded and x-forwarded-* headers set should be preserved", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		// acquire session
		login(t, rpClient, idp)

		up.requestCallback = func(r *http.Request) {
			assert.NotEmpty(t, r.Header.Get("Authorization"))
			assert.Equal(t, "for=192.168.0.99;proto=http;by=203.0.113.43", r.Header.Get("Forwarded"))
			assert.Equal(t, "192.168.0.99", r.Header.Get("X-Forwarded-For"))
			assert.Equal(t, "wonderwall.example", r.Header.Get("X-Forwarded-Host"))
			assert.Equal(t, "https", r.Header.Get("X-Forwarded-Proto"))
		}

		resp := get(t, rpClient, idp.RelyingPartyServer.URL, []header{
			{"Forwarded", "for=192.168.0.99;proto=http;by=203.0.113.43"},
			{"X-Forwarded-For", "192.168.0.99"},
			{"X-Forwarded-Host", "wonderwall.example"},
			{"X-Forwarded-Proto", "https"},
		}...)
		assertUpstreamOKResponse(t, resp)
	})

	t.Run("request should not include idToken by default", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		// acquire session
		login(t, rpClient, idp)

		up.requestCallback = func(r *http.Request) {
			assert.Empty(t, r.Header.Get("x-wonderwall-id-token"))
		}

		resp := get(t, rpClient, idp.RelyingPartyServer.URL)
		assertUpstreamOKResponse(t, resp)
	})

	t.Run("request should include idToken", func(t *testing.T) {
		cfg := mock.Config()
		cfg.UpstreamHost = up.URL.Host
		cfg.UpstreamIncludeIdToken = true
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		// acquire session
		login(t, rpClient, idp)

		up.requestCallback = func(r *http.Request) {
			assert.NotEmpty(t, r.Header.Get("x-wonderwall-id-token"))
		}

		resp := get(t, rpClient, idp.RelyingPartyServer.URL)
		assertUpstreamOKResponse(t, resp)
	})
}
