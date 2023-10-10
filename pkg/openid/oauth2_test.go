package openid

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStateMismatchError(t *testing.T) {
	for _, tt := range []struct {
		name, expected, actual string
		assertion              assert.ErrorAssertionFunc
	}{
		{"missing actual state", "expected", "", assert.Error},
		{"state mismatch", "match", "not-match", assert.Error},
		{"state match", "match", "match", assert.NoError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			actual := url.Values{
				"state": []string{tt.actual},
			}

			err := StateMismatchError(actual, tt.expected)
			tt.assertion(t, err)
		})
	}
}
