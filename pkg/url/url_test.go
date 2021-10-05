package url

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestCanonicalRedirectURL(t *testing.T) {
	r, err := http.NewRequest("GET", "http://localhost:8080/oauth2/login", nil)
	assert.NoError(t, err)

	// Default URL is /
	assert.Equal(t, "/", CanonicalRedirectURL(r))

	// HTTP Referer header is 2nd priority
	r.Header.Set("referer", "http://localhost:8080/foo/bar/baz?gnu=notunix")
	assert.Equal(t, "/foo/bar/baz", CanonicalRedirectURL(r))

	// If redirect parameter is set, use that
	v := &url.Values{}
	v.Set("redirect", "https://google.com/path/to/redirect?val1=foo&val2=bar")
	r.URL.RawQuery = v.Encode()
	assert.Equal(t, "/path/to/redirect?val1=foo&val2=bar", CanonicalRedirectURL(r))
}
