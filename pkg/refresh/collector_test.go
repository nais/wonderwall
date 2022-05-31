package refresh

import (
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"testing"
	"time"
)

func TestNewTokenCollector(t *testing.T) {
	tokenResponse := oauth2.Token{
		AccessToken:  "123456",
		TokenType:    "Bearer",
		RefreshToken: "78901",
		Expiry:       time.Time{},
	}

	for _, test := range []struct {
		name            string
		collectedTokens *TokenCollector
		accessToken     bool
		refreshToken    bool
		refreshed       bool
	}{
		{
			name:            "access_token refreshed",
			collectedTokens: NewTokenCollector(&tokenResponse, "78901", "654321"),
			accessToken:     true,
			refreshed:       true,
		},
		{
			name:            "refresh_token refreshed",
			collectedTokens: NewTokenCollector(&tokenResponse, "10987", "123456"),
			refreshToken:    true,
			refreshed:       true,
		},
		{
			name:            "token_collector refreshed",
			collectedTokens: NewTokenCollector(&tokenResponse, "10987", "654321"),
			refreshToken:    true,
			accessToken:     true,
			refreshed:       true,
		},
		{
			name:            "token_collector not refreshed",
			collectedTokens: NewTokenCollector(&tokenResponse, "78901", "123456"),
		},
	} {

		assert.Equal(t, test.refreshToken, test.collectedTokens.RefreshToken.Refreshed())
		assert.Equal(t, test.accessToken, test.collectedTokens.AccessToken.Refreshed())
		assert.Equal(t, test.refreshed, test.collectedTokens.Refreshed())
	}
}
