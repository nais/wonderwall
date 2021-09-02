package config_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
)

func TestParseIngresses(t *testing.T) {
	ingresses := []string{"https://tjenester.nav.no/sykepenger/", "https://sykepenger.nav.no/", "https://sykepenger-test.nav.no"}
	expected := []string{"", "/sykepenger"}

	prefixes := config.ParseIngresses(ingresses)
	sort.Strings(prefixes)
	assert.Equal(t, expected, prefixes)
}

func TestParseEmptyIngress(t *testing.T) {
	ingresses := []string{""}
	expected := []string{""}

	prefixes := config.ParseIngresses(ingresses)
	assert.Equal(t, expected, prefixes)
}

func TestParseDefaultIngress(t *testing.T) {
	ingresses := []string{"/"}
	expected := []string{""}

	prefixes := config.ParseIngresses(ingresses)
	assert.Equal(t, expected, prefixes)
}
