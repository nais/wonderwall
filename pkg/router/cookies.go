package router

import (
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
)

const (
	SessionCookieName     = "io.nais.wonderwall.session"
	LoginCookieName       = "io.nais.wonderwall.callback"
)

func (h *Handler) setEncryptedCookie(w http.ResponseWriter, key string, plaintext string, opts cookie.Options) error {
	encryptedCookie, err := cookie.Make(key, plaintext, opts).Encrypt(h.Crypter)
	if err != nil {
		return err
	}

	cookie.Set(w, encryptedCookie)
	return nil
}

func (h *Handler) getDecryptedCookie(r *http.Request, key string) (string, error) {
	encryptedCookie, err := cookie.Get(r, key)
	if err != nil {
		return "", fmt.Errorf("no cookie named '%s': %w", key, err)
	}

	return encryptedCookie.Decrypt(h.Crypter)
}

func (h *Handler) deleteCookie(w http.ResponseWriter, name string, opts cookie.Options) {
	cookie.Clear(w, name, opts)
}
