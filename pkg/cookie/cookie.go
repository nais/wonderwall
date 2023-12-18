package cookie

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/crypto"
)

const (
	DefaultPrefix = "io.nais.wonderwall"
	loginservice  = "selvbetjening-idtoken"
)

var (
	Login           = login(DefaultPrefix)
	LoginLegacy     = loginLegacy(DefaultPrefix)
	Logout          = logout(DefaultPrefix)
	Session         = session(DefaultPrefix)
	ErrInvalidValue = errors.New("invalid value")
	ErrDecrypt      = errors.New("unable to decrypt, key or scheme mismatch")
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

	value := base64.RawURLEncoding.EncodeToString(ciphertext)
	in.Cookie.Value = value
	return in, nil
}

func (in *Cookie) Decrypt(crypter crypto.Crypter) (string, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(in.Value)
	if err != nil {
		return "", fmt.Errorf("%w: named '%s': %w", ErrInvalidValue, in.Name, err)
	}

	plaintext, err := crypter.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: named '%s': %w", ErrDecrypt, in.Name, err)
	}

	return string(plaintext), err
}

// UnsetExpiry sets the MaxAge and Expires fields to their 'nil' values to unset them. For most user agents, this means
// that the cookie should expire at the 'end of a session', typically when the browser is closed.
//
// The cookie should still be explicitly cleared/expired whenever it is no longer needed.
func (in *Cookie) UnsetExpiry() {
	in.MaxAge = 0
	in.Expires = time.Time{}
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

func SetLegacyCookie(w http.ResponseWriter, value string, opts Options) {
	c := Make(loginservice, value, opts.
		WithSameSite(http.SameSiteLaxMode).
		WithPath("/"))
	c.UnsetExpiry()
	Set(w, c)
}

func ClearLegacyCookies(w http.ResponseWriter, opts Options) {
	// TODO - remove when legacy services are sunset and shut down
	Clear(w, loginservice, opts.
		WithSameSite(http.SameSiteLaxMode).
		WithPath("/"))
}

func ConfigureCookieNamesWithPrefix(prefix string) {
	Login = login(prefix)
	LoginLegacy = loginLegacy(prefix)
	Logout = logout(prefix)
	Session = session(prefix)
}

func withPrefix(prefix, s string) string {
	return fmt.Sprintf("%s.%s", prefix, s)
}

func login(prefix string) string {
	return withPrefix(prefix, "callback")
}

func loginLegacy(prefix string) string {
	return withPrefix(prefix, "callback.legacy")
}

func logout(prefix string) string {
	return withPrefix(prefix, "logout")
}

func session(prefix string) string {
	return withPrefix(prefix, "session")
}
