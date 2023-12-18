package cookie_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cookie"
)

func TestDefaultOptions(t *testing.T) {
	opts := cookie.DefaultOptions()

	assert.Equal(t, http.SameSiteLaxMode, opts.SameSite)
	assert.True(t, opts.Secure)
	assert.Empty(t, opts.Domain)
	assert.Empty(t, opts.Path)
}

func TestOptions_WithDomain(t *testing.T) {
	domain := ".some.domain"
	opts := cookie.Options{}.WithDomain(domain)

	assert.Equal(t, ".some.domain", opts.Domain)

	opts = cookie.Options{
		Domain: ".domain",
	}
	newOpts := opts.WithDomain(".some.other.domain")

	assert.Equal(t, ".domain", opts.Domain, "original options should be unchanged")
	assert.Equal(t, ".some.other.domain", newOpts.Domain, "copy of options should have new value")
}

func TestOptions_WithPath(t *testing.T) {
	path := "/some/path"
	opts := cookie.Options{}.WithPath(path)

	assert.Equal(t, "/some/path", opts.Path)

	opts = cookie.Options{
		Path: "/some/path",
	}
	newOpts := opts.WithPath("/some/other/path")

	assert.Equal(t, "/some/path", opts.Path, "original options should be unchanged")
	assert.Equal(t, "/some/other/path", newOpts.Path, "copy of options should have new value")
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
