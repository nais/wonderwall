package handler_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/internal/dpop"
	"github.com/nais/wonderwall/pkg/handler"
	"github.com/nais/wonderwall/pkg/handler/acr"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/session"
	urlpkg "github.com/nais/wonderwall/pkg/url"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		cfg.Upstream.Host = up.URL.Host
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
		cfg.Upstream.Host = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		// initial request without session
		target := idp.RelyingPartyServer.URL + "/"

		resp := getNavigational(t, rpClient, target)
		assertAutoLoginRedirectResponse(t, idp, resp, "/")

		// follow redirect to local login endpoint
		resp = getNavigational(t, rpClient, resp.Location.String())
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
		resp = getNavigational(t, rpClient, callbackLocation.String())
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
				cfg.Upstream.Host = up.URL.Host
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
		cfg.Upstream.Host = up.URL.Host
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		t.Run("without fetch metadata", func(t *testing.T) {
			target := idp.RelyingPartyServer.URL + "/"
			resp := get(t, rpClient, target)
			assertAutoLoginUnauthorizedResponse(t, idp, resp, "")

			referer := idp.RelyingPartyServer.URL + "/some-path"
			target = idp.RelyingPartyServer.URL + "/some-path/resource"
			resp = get(t, rpClient, target, header{"Referer", referer})
			assertAutoLoginUnauthorizedResponse(t, idp, resp, referer)
		})

		t.Run("with fetch metadata", func(t *testing.T) {
			target := idp.RelyingPartyServer.URL + "/"
			resp := get(
				t, rpClient, target,
				header{"Sec-Fetch-Mode", "cors"},
				header{"Sec-Fetch-Dest", "empty"},
			)
			assertAutoLoginUnauthorizedResponse(t, idp, resp, "")
		})
	})

	t.Run("with auto-login for navigation request without fetch metadata returns 3xx redirect", func(t *testing.T) {
		cfg := mock.Config()
		cfg.AutoLogin = true
		cfg.Upstream.Host = up.URL.Host
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
				cfg.Upstream.Host = up.URL.Host
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
							resp := getNavigational(t, rpClient, target)
							assertUpstreamUnauthorizedResponse(t, resp)
						})
					}
				})

				t.Run("non-match", func(t *testing.T) {
					for _, path := range tt.nonMatch {
						t.Run(path, func(t *testing.T) {
							target := idp.RelyingPartyServer.URL + path
							resp := getNavigational(t, rpClient, target)
							assertAutoLoginRedirectResponse(t, idp, resp, path)
						})
					}
				})
			})
		}
	})

	t.Run("request with authorization header set", func(t *testing.T) {
		cfg := mock.Config()
		cfg.Upstream.Host = up.URL.Host
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

	t.Run("request should not include id_token by default", func(t *testing.T) {
		cfg := mock.Config()
		cfg.Upstream.Host = up.URL.Host
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

	t.Run("request should include id_token", func(t *testing.T) {
		cfg := mock.Config()
		cfg.Upstream.Host = up.URL.Host
		cfg.Upstream.IncludeIDToken = true
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

	t.Run("request should strip incoming id_token if unauthenticated", func(t *testing.T) {
		cfg := mock.Config()
		cfg.Upstream.Host = up.URL.Host
		cfg.Upstream.IncludeIDToken = true
		idp := mock.NewIdentityProvider(cfg)
		defer idp.Close()

		up.SetIdentityProvider(idp)
		rpClient := idp.RelyingPartyClient()

		up.requestCallback = func(r *http.Request) {
			assert.Empty(t, r.Header.Get("x-wonderwall-id-token"))
		}

		resp := get(t, rpClient, idp.RelyingPartyServer.URL, header{
			"x-wonderwall-id-token", "some-id-token",
		})
		assertUpstreamUnauthorizedResponse(t, resp)
	})
}

func TestReverseProxyForwardingHeaders(t *testing.T) {
	forwardingHeaders := []string{
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
	}

	for _, tt := range []struct {
		name    string
		headers http.Header
	}{
		{
			name: "preserves present headers unchanged",
			headers: http.Header{
				"Forwarded":         {"for=192.168.0.99;proto=http;by=203.0.113.43", "for=198.51.100.1;proto=https;by=203.0.113.43"},
				"X-Forwarded-For":   {"192.168.0.99", "198.51.100.1"},
				"X-Forwarded-Host":  {"wonderwall.example", "example.net"},
				"X-Forwarded-Proto": {"https", "https"},
			},
		},
		{name: "does not add absent headers", headers: http.Header{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, header := range forwardingHeaders {
					assert.Equal(t, tt.headers.Values(header), r.Header.Values(header))
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()

			target, err := url.Parse(upstream.URL)
			assert.NoError(t, err)
			proxy := handler.NewUpstreamProxy(target)

			req := httptest.NewRequest(http.MethodGet, "http://wonderwall.example/", nil)
			req.Header = tt.headers.Clone()

			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, req)
			assert.Equal(t, http.StatusNoContent, recorder.Code)
		})
	}
}

func TestReverseProxyDPoP(t *testing.T) {
	const accessToken = "access-token"

	key, err := crypto.NewJwk()
	require.NoError(t, err)

	proofer, err := dpop.NewProofer(key)
	require.NoError(t, err)

	publicIngress, err := ingress.ParseIngress("https://public.example/app")
	require.NoError(t, err)

	dpopSession := session.NewSession(&session.Data{
		AccessToken:    accessToken,
		Metadata:       *session.NewMetadata(time.Hour, time.Hour),
		DPoPThumbprint: proofer.Thumbprint(),
	}, nil)
	bearerSession := session.NewSession(&session.Data{
		AccessToken: "session-token",
		Metadata:    *session.NewMetadata(time.Hour, time.Hour),
	}, nil)
	dpopSource := &reverseProxySourceStub{sess: dpopSession}

	proofCallback := func(ctx context.Context, method string, target *url.URL, nonce, accessToken string) (string, error) {
		proof, err := proofer.Proof(ctx, method, target, nonce, accessToken)
		return string(proof), err
	}

	newProxy := func(t *testing.T, upstreamHandler http.Handler, opts ...handler.ReverseProxyOption) *handler.ReverseProxy {
		t.Helper()

		upstream := httptest.NewServer(upstreamHandler)
		t.Cleanup(upstream.Close)

		upstreamURL, err := url.Parse(upstream.URL)
		require.NoError(t, err)

		return handler.NewUpstreamProxy(upstreamURL, opts...)
	}

	t.Run("generates an upstream proof with the public URL and access token", func(t *testing.T) {
		var received *http.Request
		proxy := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received = r
			w.WriteHeader(http.StatusNoContent)
		}),
			handler.WithDPoPProof(proofCallback),
		)

		req := httptest.NewRequest(http.MethodPost, "https://internal.example/app/resource?query=value", nil)
		req.Header.Set("DPoP", "caller-proof")
		req = mw.RequestWithIngress(req, *publicIngress)

		proxy.Handler(dpopSource, httptest.NewRecorder(), req)

		require.NotNil(t, received)
		assert.Equal(t, "DPoP "+accessToken, received.Header.Get("Authorization"))
		assert.NotEqual(t, "caller-proof", received.Header.Get("DPoP"))

		proof, err := jwt.ParseInsecure([]byte(received.Header.Get("DPoP")))
		require.NoError(t, err)

		var htu, ath string
		require.NoError(t, proof.Get("htu", &htu))
		require.NoError(t, proof.Get("ath", &ath))
		assert.Equal(t, "https://public.example/app/resource", htu)

		digest := sha256.Sum256([]byte(accessToken))
		assert.Equal(t, base64.RawURLEncoding.EncodeToString(digest[:]), ath)
	})

	t.Run("uses an upstream nonce on the next request", func(t *testing.T) {
		var proofs []string
		proxy := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proofs = append(proofs, r.Header.Get("DPoP"))
			if len(proofs) == 1 {
				w.Header().Set("DPoP-Nonce", "upstream-nonce")
			}
			w.WriteHeader(http.StatusNoContent)
		}),
			handler.WithDPoPProof(proofCallback),
		)

		for range 2 {
			req := httptest.NewRequest(http.MethodGet, "https://internal.example/app", nil)
			req = mw.RequestWithIngress(req, *publicIngress)
			proxy.Handler(dpopSource, httptest.NewRecorder(), req)
		}

		require.Len(t, proofs, 2)
		firstProof, err := jwt.ParseInsecure([]byte(proofs[0]))
		require.NoError(t, err)
		assert.False(t, firstProof.Has("nonce"))

		secondProof, err := jwt.ParseInsecure([]byte(proofs[1]))
		require.NoError(t, err)

		var nonce string
		require.NoError(t, secondProof.Get("nonce", &nonce))
		assert.Equal(t, "upstream-nonce", nonce)
	})

	t.Run("ignores a nonce from a transparent DPoP request", func(t *testing.T) {
		var proofs []string
		proxy := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proofs = append(proofs, r.Header.Get("DPoP"))
			w.Header().Set("DPoP-Nonce", "caller-nonce")
			w.WriteHeader(http.StatusNoContent)
		}),
			handler.WithDPoPProof(proofCallback),
		)

		transparent := httptest.NewRequest(http.MethodGet, "https://internal.example/app", nil)
		transparent.Header.Set("Authorization", "DPoP caller-token")
		transparent.Header.Set("DPoP", "caller-proof")
		transparent = mw.RequestWithIngress(transparent, *publicIngress)
		proxy.Handler(&reverseProxySourceStub{err: session.ErrNotFound}, httptest.NewRecorder(), transparent)

		authenticated := httptest.NewRequest(http.MethodGet, "https://internal.example/app", nil)
		authenticated = mw.RequestWithIngress(authenticated, *publicIngress)
		proxy.Handler(dpopSource, httptest.NewRecorder(), authenticated)

		require.Len(t, proofs, 2)

		proof, err := jwt.ParseInsecure([]byte(proofs[1]))
		require.NoError(t, err)

		assert.False(t, proof.Has("nonce"))
	})

	t.Run("presents credentials based on session and proxy configuration", func(t *testing.T) {
		for _, test := range []struct {
			name                  string
			session               *session.Session
			sessionError          error
			expectedAuthorization string
			expectedProof         string
			options               []handler.ReverseProxyOption
		}{
			{
				name:                  "without session",
				sessionError:          session.ErrNotFound,
				expectedAuthorization: "DPoP caller-token",
				expectedProof:         "caller-proof",
			},
			{
				name:                  "with bearer session",
				session:               bearerSession,
				expectedAuthorization: "Bearer session-token",
				expectedProof:         "caller-proof",
			},
			{
				name:                  "with bearer session and upstream DPoP enabled",
				session:               bearerSession,
				expectedAuthorization: "Bearer session-token",
				expectedProof:         "caller-proof",
				options:               []handler.ReverseProxyOption{handler.WithDPoPProof(proofCallback)},
			},
			{
				name:                  "with DPoP session and upstream DPoP disabled",
				session:               dpopSession,
				expectedAuthorization: "Bearer " + accessToken,
				expectedProof:         "caller-proof",
			},
			{
				name:                  "with nil proof option",
				session:               dpopSession,
				expectedAuthorization: "Bearer " + accessToken,
				expectedProof:         "caller-proof",
				options:               []handler.ReverseProxyOption{handler.WithDPoPProof(nil)},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				var authorization, proof string
				proxy := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					authorization = r.Header.Get("Authorization")
					proof = r.Header.Get("DPoP")
					w.WriteHeader(http.StatusNoContent)
				}), test.options...)

				source := &reverseProxySourceStub{sess: test.session, err: test.sessionError}

				req := httptest.NewRequest(http.MethodGet, "http://public.example/resource", nil)
				req.Header.Set("Authorization", "DPoP caller-token")
				req.Header.Set("DPoP", "caller-proof")

				proxy.Handler(source, httptest.NewRecorder(), req)

				assert.Equal(t, test.expectedAuthorization, authorization)
				assert.Equal(t, test.expectedProof, proof)
			})
		}
	})

	t.Run("requires ingress", func(t *testing.T) {
		proxy := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
			handler.WithDPoPProof(proofCallback),
		)
		recorder := httptest.NewRecorder()
		proxy.Handler(dpopSource, recorder, httptest.NewRequest(http.MethodGet, "https://internal.example/app", nil))

		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	})
}

type reverseProxySourceStub struct {
	sess *session.Session
	err  error
}

func (s *reverseProxySourceStub) GetAcrHandler() *acr.Handler { return &acr.Handler{} }
func (s *reverseProxySourceStub) GetAutoLogin() *autologin.AutoLogin {
	return &autologin.AutoLogin{}
}
func (s *reverseProxySourceStub) GetPath(*http.Request) string { return "" }
func (s *reverseProxySourceStub) GetSession(*http.Request) (*session.Session, error) {
	return s.sess, s.err
}

var _ handler.ReverseProxySource = (*reverseProxySourceStub)(nil)

type upstream struct {
	Server          *httptest.Server
	URL             *url.URL
	idp             *mock.IdentityProvider
	reverseProxyURL *url.URL
	requestCallback func(r *http.Request)
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
