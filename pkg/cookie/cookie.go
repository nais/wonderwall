package cookie

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/crypto"
)

const (
	Session     = "io.nais.wonderwall.session"
	Login       = "io.nais.wonderwall.callback"
	LoginLegacy = "io.nais.wonderwall.callback.legacy"
)

type Cookie struct {
	*http.Cookie
}

func (in *Cookie) Encrypt(crypter crypto.Crypter) (*Cookie, error) {
	plaintext := []byte(in.Cookie.Value)
	ciphertext, err := crypter.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt cookie '%s': %w", in.Cookie.Name, err)
	}

	value := base64.StdEncoding.EncodeToString(ciphertext)
	in.Cookie.Value = value
	return in, nil
}

func (in *Cookie) Decrypt(crypter crypto.Crypter) (string, error) {
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
	expires := time.Unix(0, 0)
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

	if len(opts.Domain) > 0 {
		cookie.Domain = opts.Domain
	}

	if len(opts.Path) > 0 {
		cookie.Path = opts.Path
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

func GetDecrypted(r *http.Request, key string, crypter crypto.Crypter) (string, error) {
	encryptedCookie, err := Get(r, key)
	if err != nil {
		return "", err
	}

	return encryptedCookie.Decrypt(crypter)
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

	if len(opts.Domain) > 0 {
		cookie.Domain = opts.Domain
	}

	if len(opts.Path) > 0 {
		cookie.Path = opts.Path
	}

	return &Cookie{cookie}
}

func Set(w http.ResponseWriter, cookie *Cookie) {
	http.SetCookie(w, cookie.Cookie)
}

func EncryptAndSet(w http.ResponseWriter, key, value string, opts Options, crypter crypto.Crypter) error {
	encryptedCookie, err := Make(key, value, opts).Encrypt(crypter)
	if err != nil {
		return err
	}

	Set(w, encryptedCookie)
	return nil
}
