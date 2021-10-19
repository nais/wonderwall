package router_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router"
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
			error: router.InvalidSecurityLevelError,
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
			error: router.InvalidLocaleError,
		},
	}

	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			req, err := http.NewRequest("GET", test.url, nil)
			assert.NoError(t, err)

			params, err := openid.GenerateLoginParameters()
			assert.NoError(t, err)

			provider := mock.NewTestProvider()
			handler := newHandler(provider)
			_, err = handler.LoginURL(req, params)

			if test.error != nil {
				assert.True(t, errors.Is(err, test.error))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
