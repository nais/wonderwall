package router_test

import (
	"errors"
	"github.com/nais/wonderwall/pkg/auth"
	error2 "github.com/nais/wonderwall/pkg/errorhandler"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestLoginURL(t *testing.T) {
	type loginURLTest struct {
		url   string
		error error
	}

	tests := []loginURLTest{
		{
			url:   "http://localhost:1234/oauth2/login?level=Level4",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login?level=NoLevel",
			error: error2.InvalidSecurityLevelError,
		},
		{
			url:   "http://localhost:1234/oauth2/login?locale=nb",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login?level=Level4&locale=nb",
			error: nil,
		},
		{
			url:   "http://localhost:1234/oauth2/login?locale=es",
			error: error2.InvalidLocaleError,
		},
	}

	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			cfg := defaultConfig()
			req, err := http.NewRequest("GET", test.url, nil)
			assert.NoError(t, err)

			params, err := auth.GenerateLoginParameters()
			assert.NoError(t, err)

			handler := handler(cfg)
			_, err = handler.LoginURL(req, params)

			if test.error != nil {
				assert.True(t, errors.Is(err, test.error))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
