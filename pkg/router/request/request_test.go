package request_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/router/request"
)

func TestCanonicalRedirectURL(t *testing.T) {
	r, err := http.NewRequest("GET", "http://localhost:8080/oauth2/login", nil)
	assert.NoError(t, err)

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
				assert.Equal(t, test.expected, request.CanonicalRedirectURL(r, test.ingress))
			})
		}
	})

	// Default path is /some-path
	ingress := "http://localhost:8080/some-path"

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
				assert.Equal(t, test.expected, request.CanonicalRedirectURL(r, ingress))
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
				assert.Equal(t, test.expected, request.CanonicalRedirectURL(r, ingress))
			})
		}
	})
}
