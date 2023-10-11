package acr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAcr(t *testing.T) {
	for _, tt := range []struct {
		name     string
		expected string
		actual   string
		wantErr  bool
	}{
		{"no mapping found, not equal", "some-value", "some-other-value", true},
		{"no mapping found, expected equals actual", "some-value", "some-value", false},
		{"Level3", "Level3", "Level3", false},
		{"Level3, higher acr accepted", "Level3", "Level4", false},
		{"Level3, higher acr accepted 2", "Level3", "idporten-loa-high", false},
		{"Level3, no matching value", "Level3", "Level2", true},
		{"Level3 -> idporten-loa-substantial", "Level3", "idporten-loa-substantial", false},
		{"idporten-loa-substantial", "idporten-loa-substantial", "idporten-loa-substantial", false},
		{"idporten-loa-substantial -> Level3", "idporten-loa-substantial", "Level3", false},
		{"idporten-loa-substantial, higher acr accepted", "idporten-loa-substantial", "Level4", false},
		{"idporten-loa-substantial, higher acr accepted 2", "idporten-loa-substantial", "idporten-loa-high", false},
		{"Level4", "Level4", "Level4", false},
		{"Level4, lower acr not accepted", "Level4", "Level3", true},
		{"Level4, lower acr not accepted 2", "Level4", "idporten-loa-substantial", true},
		{"Level4, no matching value", "Level4", "Level5", true},
		{"Level4 -> idporten-loa-high", "Level4", "idporten-loa-high", false},
		{"idporten-loa-high", "idporten-loa-high", "idporten-loa-high", false},
		{"idporten-loa-high -> Level4", "idporten-loa-high", "Level4", false},
		{"idporten-loa-high, lower acr not accepted", "idporten-loa-high", "Level3", true},
		{"idporten-loa-high, lower acr not accepted 2", "idporten-loa-high", "idporten-loa-substantial", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.expected, tt.actual)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
