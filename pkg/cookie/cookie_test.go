package cookie_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
)

var encryptionKey = `G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq` // 256 bits key

func TestMake(t *testing.T) {
	opts := cookie.DefaultOptions()

	name := "some-cookie"
	value := "some-value"

	result := cookie.Make(name, value, opts)

	assert.True(t, result.Expires.IsZero())
	assert.Equal(t, 0, result.MaxAge)
	assert.True(t, result.HttpOnly)
	assert.Equal(t, name, result.Name)
	assert.Equal(t, value, result.Value)
	assert.Equal(t, opts.SameSite, result.SameSite)
	assert.Equal(t, opts.Secure, result.Secure)
	assert.Equal(t, "/", result.Path)
	assert.Empty(t, result.Domain)
}

func TestMakeWithDomain(t *testing.T) {
	opts := cookie.DefaultOptions().WithDomain(".some.domain")
	result := cookie.Make("some-cookie", "some-value", opts)
	assert.Equal(t, ".some.domain", result.Domain)
}

func TestMakeWithPath(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "path with multiple subpaths",
			path: "/some/path",
			want: "/some/path",
		},
		{
			name: "empty path",
			path: "",
			want: "/",
		},
		{
			name: "root path",
			path: "/",
			want: "/",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := cookie.DefaultOptions().WithPath(test.path)
			result := cookie.Make("some-cookie", "some-value", opts)
			assert.Equal(t, test.want, result.Path)
		})
	}
}

func TestClear(t *testing.T) {
	opts := cookie.DefaultOptions()
	name := "some-name"

	writer := httptest.NewRecorder()
	cookie.Clear(writer, name, opts)

	cookies := writer.Result().Cookies()

	var result *http.Cookie
	for _, c := range cookies {
		if c.Name == name {
			result = c
		}
	}

	assert.NotNil(t, result)
	assert.True(t, result.Expires.Before(time.Now()))
	assert.True(t, result.Expires.Equal(time.Unix(0, 0)))
	assert.Equal(t, -1, result.MaxAge)
	assert.True(t, result.HttpOnly)
	assert.Equal(t, name, result.Name)
	assert.Equal(t, "", result.Value)
	assert.Equal(t, opts.SameSite, result.SameSite)
	assert.Equal(t, opts.Secure, result.Secure)
	assert.Equal(t, "/", result.Path)
}

func TestClearWithDomain(t *testing.T) {
	opts := cookie.DefaultOptions().WithDomain(".some.domain")
	name := "some-cookie"

	writer := httptest.NewRecorder()
	cookie.Clear(writer, name, opts)

	cookies := writer.Result().Cookies()

	var result *http.Cookie
	for _, c := range cookies {
		if c.Name == name {
			result = c
		}
	}

	assert.NotNil(t, result)
	assert.Equal(t, "some.domain", result.Domain)
}

func TestClearWithPath(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "path with multiple subpaths",
			path: "/some/path",
			want: "/some/path",
		},
		{
			name: "empty path",
			path: "",
			want: "/",
		},
		{
			name: "root path",
			path: "/",
			want: "/",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := cookie.DefaultOptions().WithPath(test.path)
			name := "some-cookie"

			writer := httptest.NewRecorder()
			cookie.Clear(writer, name, opts)

			cookies := writer.Result().Cookies()

			var result *http.Cookie
			for _, c := range cookies {
				if c.Name == name {
					result = c
				}
			}

			assert.NotNil(t, result)
			assert.Equal(t, test.want, result.Path)
		})
	}
}

func TestCookie_Encrypt(t *testing.T) {
	crypter := crypto.NewCrypter([]byte(encryptionKey))

	opts := cookie.DefaultOptions()
	name := "some-name"
	value := "some-value"

	plaintextCookie := cookie.Make(name, value, opts)
	encryptedCookie, err := plaintextCookie.Encrypt(crypter)
	assert.NoError(t, err)
	assert.NotEqual(t, value, encryptedCookie.Value)
}

func TestCookie_Decrypt(t *testing.T) {
	crypter := crypto.NewCrypter([]byte(encryptionKey))

	opts := cookie.DefaultOptions()
	name := "some-name"
	value := "some-value"

	plaintextCookie := cookie.Make(name, value, opts)
	encryptedCookie, err := plaintextCookie.Encrypt(crypter)
	assert.NoError(t, err)
	assert.NotEqual(t, value, encryptedCookie.Value)

	plaintext, err := encryptedCookie.Decrypt(crypter)
	assert.NoError(t, err)
	assert.Equal(t, value, plaintext)
}

func TestCookieNames(t *testing.T) {
	assert.Equal(t, "io.nais.wonderwall.callback", cookie.Login)
	assert.Equal(t, "io.nais.wonderwall.logout", cookie.Logout)
	assert.Equal(t, "io.nais.wonderwall.session", cookie.Session)

	cookie.ConfigureCookieNamesWithPrefix("some-prefix")
	assert.Equal(t, "some-prefix.callback", cookie.Login)
	assert.Equal(t, "some-prefix.logout", cookie.Logout)
	assert.Equal(t, "some-prefix.session", cookie.Session)
}
