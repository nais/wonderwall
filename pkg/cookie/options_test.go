package cookie_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cookie"
)

func TestDefaultOptions(t *testing.T) {
	opts := cookie.DefaultOptions()

	assert.Equal(t, http.SameSiteLaxMode, opts.SameSite)
	assert.True(t, opts.Secure)
	assert.Empty(t, opts.ExpiresIn)
}

func TestOptions_WithExpiresIn(t *testing.T) {
	expiresIn := 1 * time.Minute
	opts := cookie.Options{}.WithExpiresIn(expiresIn)

	assert.Equal(t, 1*time.Minute, opts.ExpiresIn)

	opts = cookie.Options{
		ExpiresIn: 2 * time.Minute,
	}
	newOpts := opts.WithExpiresIn(expiresIn)

	assert.Equal(t, 2*time.Minute, opts.ExpiresIn, "original options should be unchanged")
	assert.Equal(t, 1*time.Minute, newOpts.ExpiresIn, "copy of options should have new value")
}

func TestOptions_WithSameSite(t *testing.T) {
	sameSite := http.SameSiteDefaultMode
	opts := cookie.Options{}.WithSameSite(sameSite)

	assert.Equal(t, http.SameSiteDefaultMode, opts.SameSite)

	opts = cookie.Options{
		SameSite: http.SameSiteLaxMode,
	}
	newOpts := opts.WithSameSite(sameSite)

	assert.Equal(t, http.SameSiteLaxMode, opts.SameSite, "original options should be unchanged")
	assert.Equal(t, http.SameSiteDefaultMode, newOpts.SameSite, "copy of options should have new value")
}

func TestOptions_WithSecure(t *testing.T) {
	opts := cookie.Options{}.WithSecure(true)

	assert.True(t, opts.Secure)

	opts = cookie.Options{
		Secure: false,
	}
	newOpts := opts.WithSecure(true)

	assert.False(t, opts.Secure, "original options should be unchanged")
	assert.True(t, newOpts.Secure, "copy of options should have new value")
}
