package url_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	urlpkg "github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/mock"
)

func TestCanonicalRedirect(t *testing.T) {
	t.Run("default redirect", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			ingress  string
			expected string
		}{
			{
				name:     "root with trailing slash",
				ingress:  "http://localhost:8080/",
				expected: "/",
			},
			{
				name:     "root without trailing slash",
				ingress:  "http://localhost:8080",
				expected: "/",
			},
			{
				name:     "path with trailing slash",
				ingress:  "http://localhost:8080/path/",
				expected: "/path",
			},
			{
				name:     "path without trailing slash",
				ingress:  "http://localhost:8080/path",
				expected: "/path",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, test.ingress+"/oauth2/login", nil)
				parsed, err := ingress.ParseIngress(test.ingress)
				assert.NoError(t, err)

				r = mw.RequestWithPath(r, parsed.Path())

				assert.Equal(t, test.expected, urlpkg.CanonicalRedirect(r))
			})
		}
	})

	// Default path is /some-path
	defaultIngress := "http://localhost:8080/some-path"
	r := httptest.NewRequest(http.MethodGet, defaultIngress+"/oauth2/login", nil)
	r = mw.RequestWithPath(r, "/some-path")

	// HTTP Referer header is 2nd priority
	t.Run("Referer header is set", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			value    string
			expected string
		}{
			{
				name:     "full URL",
				value:    "http://localhost:8080/foo/bar/baz",
				expected: "/foo/bar/baz",
			},
			{
				name:     "full URL with query parameters",
				value:    "http://localhost:8080/foo/bar/baz?gnu=notunix",
				expected: "/foo/bar/baz?gnu=notunix",
			},
			{
				name:     "absolute path",
				value:    "/foo/bar/baz",
				expected: "/foo/bar/baz",
			},
			{
				name:     "absolute path with query parameters",
				value:    "/foo/bar/baz?gnu=notunix",
				expected: "/foo/bar/baz?gnu=notunix",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				r.Header.Set("Referer", test.value)
				assert.Equal(t, test.expected, urlpkg.CanonicalRedirect(r))
			})
		}
	})

	// If redirect parameter is set, use that
	t.Run("redirect parameter is set", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			value    string
			expected string
		}{
			{
				name:     "complete url with parameters",
				value:    "http://localhost:8080/path/to/redirect?val1=foo&val2=bar",
				expected: "/path/to/redirect?val1=foo&val2=bar",
			},
			{
				name:     "root url with trailing slash",
				value:    "http://localhost:8080/",
				expected: "/",
			},
			{
				name:     "root url without trailing slash",
				value:    "http://localhost:8080",
				expected: "/",
			},
			{
				name:     "url path with trailing slash",
				value:    "http://localhost:8080/path/",
				expected: "/path/",
			},
			{
				name:     "url path without trailing slash",
				value:    "http://localhost:8080/path",
				expected: "/path",
			},
			{
				name:     "absolute path",
				value:    "/path",
				expected: "/path",
			},
			{
				name:     "absolute path with query parameters",
				value:    "/path?gnu=notunix",
				expected: "/path?gnu=notunix",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				v := &url.Values{}
				v.Set("redirect", test.value)
				r.URL.RawQuery = v.Encode()
				assert.Equal(t, test.expected, urlpkg.CanonicalRedirect(r))
			})
		}
	})
}

func TestLoginURL(t *testing.T) {
	for _, test := range []struct {
		name           string
		prefix         string
		redirectTarget string
		want           string
	}{
		{
			name:           "no prefix",
			prefix:         "",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/oauth2/login?redirect=https://test.example.com?some=param&other=param2",
		},
		{
			name:           "with prefix",
			prefix:         "/path",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/path/oauth2/login?redirect=https://test.example.com?some=param&other=param2",
		},
		{
			name:           "we need to go deeper",
			prefix:         "/deeper/path",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/deeper/path/oauth2/login?redirect=https://test.example.com?some=param&other=param2",
		},
		{
			name:           "relative target",
			prefix:         "",
			redirectTarget: "/path?some=param&other=param2",
			want:           "/oauth2/login?redirect=/path?some=param&other=param2",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			loginUrl := urlpkg.LoginURL(test.prefix, test.redirectTarget)
			assert.Equal(t, test.want, loginUrl)
		})
	}
}

func TestClient_CallbackURL(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"https://nav.no",
		"https://nav.no/test",
		"https://nav.no/dagpenger",
		"https://nav.no/dagpenger/soknad",
	}
	openidConfig := mock.NewTestConfiguration(cfg)

	for _, test := range []struct {
		input string
		want  string
		err   error
	}{
		{
			input: "https://nav.no/",
			want:  "https://nav.no/oauth2/callback",
		},
		{
			input: "https://nav.no/test",
			want:  "https://nav.no/test/oauth2/callback",
		},
		{
			input: "https://nav.no/dagpenger",
			want:  "https://nav.no/dagpenger/oauth2/callback",
		},
		{
			input: "https://nav.no/dagpenger/soknad",
			want:  "https://nav.no/dagpenger/soknad/oauth2/callback",
		},
		{
			input: "https://not-nav.no/",
			err:   fmt.Errorf("request host does not match any configured ingresses"),
		},
	} {
		t.Run(test.input, func(t *testing.T) {
			req := mock.NewGetRequest(test.input, openidConfig)

			actual, err := urlpkg.CallbackURL(req)
			if test.err != nil {
				assert.EqualError(t, err, test.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.want, actual)
			}
		})
	}
}

func TestClient_LogoutCallbackURL(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"https://nav.no",
		"https://nav.no/test",
		"https://nav.no/dagpenger",
		"https://nav.no/dagpenger/soknad",
	}
	openidConfig := mock.NewTestConfiguration(cfg)

	for _, test := range []struct {
		input string
		want  string
		err   error
	}{
		{
			input: "https://nav.no/",
			want:  "https://nav.no/oauth2/logout/callback",
		},
		{
			input: "https://nav.no/test",
			want:  "https://nav.no/test/oauth2/logout/callback",
		},
		{
			input: "https://nav.no/dagpenger",
			want:  "https://nav.no/dagpenger/oauth2/logout/callback",
		},
		{
			input: "https://nav.no/dagpenger/soknad",
			want:  "https://nav.no/dagpenger/soknad/oauth2/logout/callback",
		},
		{
			input: "https://not-nav.no/",
			err:   fmt.Errorf("request host does not match any configured ingresses"),
		},
	} {
		t.Run(test.input, func(t *testing.T) {
			req := mock.NewGetRequest(test.input, openidConfig)

			actual, err := urlpkg.LogoutCallbackURL(req)
			if test.err != nil {
				assert.EqualError(t, err, test.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.want, actual)
			}
		})
	}
}
