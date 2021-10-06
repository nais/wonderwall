package request_test

import (
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/request"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestCanonicalRedirectURL(t *testing.T) {
	r, err := http.NewRequest("GET", "http://localhost:8080/oauth2/login", nil)
	assert.NoError(t, err)

	// Default URL is /
	assert.Equal(t, "/", request.CanonicalRedirectURL(r))

	// HTTP Referer header is 2nd priority
	r.Header.Set("referer", "http://localhost:8080/foo/bar/baz?gnu=notunix")
	assert.Equal(t, "/foo/bar/baz", request.CanonicalRedirectURL(r))

	// If redirect parameter is set, use that
	v := &url.Values{}
	v.Set("redirect", "https://google.com/path/to/redirect?val1=foo&val2=bar")
	r.URL.RawQuery = v.Encode()
	assert.Equal(t, "/path/to/redirect?val1=foo&val2=bar", request.CanonicalRedirectURL(r))
}

func TestLoginURLParameter(t *testing.T) {
	for _, test := range []struct {
		name      string
		parameter string
		fallback  string
		supported config.Supported
		url       string
		expectErr error
		expected  string
	}{
		{
			name:     "no URL parameter should use fallback value",
			url:      "http://localhost:8080/oauth2/login",
			expected: "valid",
		},
		{
			name:     "non-matching URL parameter should be ignored",
			url:      "http://localhost:8080/oauth2/login?other_param=value2",
			expected: "valid",
		},
		{
			name:     "matching URL parameter should take precedence",
			url:      "http://localhost:8080/oauth2/login?param=valid2",
			expected: "valid2",
		},
		{
			name:      "invalid URL parameter value should return error",
			url:       "http://localhost:8080/oauth2/login?param=invalid",
			expectErr: request.InvalidLoginParameterError,
		},
		{
			name:      "invalid fallback value should return error",
			fallback:  "invalid",
			url:       "http://localhost:8080/oauth2/login",
			expectErr: request.InvalidLoginParameterError,
		},
		{
			name:      "no supported values should return error",
			url:       "http://localhost:8080/oauth2/login",
			supported: config.Supported{""},
			expectErr: request.InvalidLoginParameterError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", test.url, nil)
			assert.NoError(t, err)

			// default test values
			parameter := "param"
			fallback := "valid"
			supported := config.Supported{"valid", "valid2"}

			if len(test.parameter) > 0 {
				parameter = test.parameter
			}

			if len(test.fallback) > 0 {
				fallback = test.fallback
			}

			if len(test.supported) > 0 {
				supported = test.supported
			}

			val, err := request.LoginURLParameter(r, parameter, fallback, supported)

			if test.expectErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, val)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
