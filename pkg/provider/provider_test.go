package provider_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/provider"
)

func TestRedirectURI(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
		err error
	}{
		{
			input: "https://nav.no/dagpenger",
			want:  "https://nav.no/dagpenger/oauth2/callback",
		},
		{
			input: "https://nav.no/dagpenger/soknad",
			want:  "https://nav.no/dagpenger/soknad/oauth2/callback",
		},
		{
			input: "https://nav.no",
			want:  "https://nav.no/oauth2/callback",
		},
		{
			input: "https://nav.no/",
			want:  "https://nav.no/oauth2/callback",
		},
		{
			input: "",
			err: fmt.Errorf("ingress cannot be empty"),
		},
	} {
		actual, err := provider.RedirectURI(test.input)
		if test.err != nil {
			assert.EqualError(t, err, test.err.Error())
		} else {
			assert.NoError(t, err)
		}

		assert.Equal(t, test.want, actual)
	}
}
