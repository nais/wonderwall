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

var (
	encryptionKey = `G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq` // 256 bits AES
)

func TestMake(t *testing.T) {
	expiresIn := 5 * time.Minute
	opts := cookie.DefaultOptions().WithExpiresIn(expiresIn)

	name := "some-cookie"
	value := "some-value"

	result := cookie.Make(name, value, opts)

	shouldExpireBefore := time.Now().Add(expiresIn)
	assert.True(t, result.Expires.Before(shouldExpireBefore))
	assert.Equal(t, int(opts.ExpiresIn.Seconds()), result.MaxAge)
	assert.True(t, result.HttpOnly)
	assert.Equal(t, name, result.Name)
	assert.Equal(t, value, result.Value)
	assert.Equal(t, opts.SameSite, result.SameSite)
	assert.Equal(t, opts.Secure, result.Secure)
	assert.Equal(t, "/", result.Path)
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

func TestCookie_Encrypt(t *testing.T) {
	crypter := crypto.NewCrypter([]byte(encryptionKey))

	opts := cookie.DefaultOptions().WithExpiresIn(1 * time.Minute)
	name := "some-name"
	value := "some-value"

	plaintextCookie := cookie.Make(name, value, opts)
	encryptedCookie, err := plaintextCookie.Encrypt(crypter)
	assert.NoError(t, err)
	assert.NotEqual(t, value, encryptedCookie.Value)
}

func TestCookie_Decrypt(t *testing.T) {
	crypter := crypto.NewCrypter([]byte(encryptionKey))

	opts := cookie.DefaultOptions().WithExpiresIn(1 * time.Minute)
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
