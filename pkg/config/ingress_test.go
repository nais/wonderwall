package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
)

func TestParseIngress(t *testing.T) {
	for _, test := range []struct{
		ingress string
		want string
	}{
		{
			ingress: "https://tjenester.nav.no/sykepenger/",
			want:    "/sykepenger",
		},
		{
			ingress: "https://tjenester.nav.no/sykepenger/test",
			want:    "/sykepenger/test",
		},
		{
			ingress: "https://tjenester.nav.no/test/sykepenger/",
			want:    "/test/sykepenger",
		},
		{
			ingress: "https://sykepenger.nav.no/",
			want:    "",
		},
		{
			ingress: "https://sykepenger-test.nav.no",
			want:    "",
		},

	} {
		t.Run(test.ingress, func(t *testing.T) {
			prefix := config.ParseIngress(test.ingress)
			assert.Equal(t, test.want, prefix)
		})
	}
}

func TestParseEmptyIngress(t *testing.T) {
	ingress := ""
	expected := ""

	prefix := config.ParseIngress(ingress)
	assert.Equal(t, expected, prefix)
}

func TestParseDefaultIngress(t *testing.T) {
	ingress := "/"
	expected := ""

	prefix := config.ParseIngress(ingress)
	assert.Equal(t, expected, prefix)
}
