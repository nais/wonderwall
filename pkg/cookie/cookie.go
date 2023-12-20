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
	Logout          = logout(DefaultPrefix)
	Retry           = retry(DefaultPrefix)
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
	cookie := &http.Cookie{
		HttpOnly: true,
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
	Logout = logout(prefix)
	Retry = retry(prefix)
	Session = session(prefix)
}

func withPrefix(prefix, s string) string {
	return fmt.Sprintf("%s.%s", prefix, s)
}

func login(prefix string) string {
	return withPrefix(prefix, "callback")
}

func logout(prefix string) string {
	return withPrefix(prefix, "logout")
}

func retry(prefix string) string {
	return withPrefix(prefix, "retry")
}

func session(prefix string) string {
	return withPrefix(prefix, "session")
}
