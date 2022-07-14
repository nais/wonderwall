package config_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/router/paths"
)

func TestRedirectURI(t *testing.T) {
	for _, test := range []struct {
		input string
		path  string
		want  string
		err   error
	}{
		{
			input: "https://nav.no/dagpenger",
			path:  paths.Callback,
			want:  "https://nav.no/dagpenger/oauth2/callback",
		},
		{
			input: "https://nav.no/dagpenger/soknad",
			path:  paths.Callback,
			want:  "https://nav.no/dagpenger/soknad/oauth2/callback",
		},
		{
			input: "https://nav.no",
			path:  paths.Callback,
			want:  "https://nav.no/oauth2/callback",
		},
		{
			input: "https://nav.no/",
			path:  paths.Callback,
			want:  "https://nav.no/oauth2/callback",
		},
		{
			input: "https://nav.no/",
			path:  paths.LogoutCallback,
			want:  "https://nav.no/oauth2/logout/callback",
		},
		{
			input: "",
			err:   fmt.Errorf("ingress cannot be empty"),
		},
	} {
		actual, err := config.RedirectURI(test.input, test.path)
		if test.err != nil {
			assert.EqualError(t, err, test.err.Error())
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.want, actual)
		}
	}
}
