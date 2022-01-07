package cookie

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/crypto"
)

type Cookie struct {
	*http.Cookie
}

func (in Cookie) Encrypt(crypter crypto.Crypter) (*Cookie, error) {
	plaintext := []byte(in.Cookie.Value)
	ciphertext, err := crypter.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt cookie '%s': %w", in.Cookie.Name, err)
	}

	value := base64.StdEncoding.EncodeToString(ciphertext)

	encryptedCookie := in.Cookie
	encryptedCookie.Value = value

	return &Cookie{encryptedCookie}, nil
}

func (in Cookie) Decrypt(crypter crypto.Crypter) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(in.Value)
	if err != nil {
		return "", fmt.Errorf("value for cookie '%s' is not base64 encoded: %w", in.Name, err)
	}

	plaintext, err := crypter.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt cookie '%s': %w", in.Name, err)
	}

	return string(plaintext), err
}

func Clear(w http.ResponseWriter, name string, opts Options) {
	expires := time.Now().Add(-7 * 24 * time.Hour)
	maxAge := -1

	cookie := &http.Cookie{
		Expires:  expires,
		HttpOnly: true,
		MaxAge:   maxAge,
		Name:     name,
		Path:     "/",
		SameSite: opts.SameSite,
		Secure:   opts.Secure,
	}

	http.SetCookie(w, cookie)
}

func Get(r *http.Request, key string) (*Cookie, error) {
	cookie, err := r.Cookie(key)
	if err != nil {
		return nil, fmt.Errorf("no cookie named '%s': %w", key, err)
	}

	return &Cookie{cookie}, nil
}

func Make(name, value string, opts Options) *Cookie {
	expires := time.Now().Add(opts.ExpiresIn)
	maxAge := int(opts.ExpiresIn.Seconds())

	cookie := &http.Cookie{
		Expires:  expires,
		HttpOnly: true,
		MaxAge:   maxAge,
		Name:     name,
		Path:     "/",
		SameSite: opts.SameSite,
		Secure:   opts.Secure,
		Value:    value,
	}

	return &Cookie{cookie}
}

func Set(w http.ResponseWriter, cookie *Cookie) {
	http.SetCookie(w, cookie.Cookie)
}
