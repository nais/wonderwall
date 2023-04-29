package openid

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
		{"Level3, no matching value", "Level3", "Level2", true},
		{"Level4", "Level4", "Level4", false},
		{"Level4, lower acr not accepted", "Level4", "Level3", true},
		{"Level4, no matching value", "Level4", "Level5", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAcr(tt.expected, tt.actual)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
