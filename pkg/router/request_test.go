package router_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/router"
)

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
			expectErr: router.InvalidLoginParameterError,
		},
		{
			name:      "invalid fallback value should return error",
			fallback:  "invalid",
			url:       "http://localhost:8080/oauth2/login",
			expectErr: router.InvalidLoginParameterError,
		},
		{
			name:      "no supported values should return error",
			url:       "http://localhost:8080/oauth2/login",
			supported: config.Supported{""},
			expectErr: router.InvalidLoginParameterError,
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

			val, err := router.LoginURLParameter(r, parameter, fallback, supported)

			if test.expectErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, val)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
