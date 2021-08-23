package router

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

type Cookie struct {
	name      string
	value     string
	expiresIn time.Duration
}

type CallbackCookies struct {
	State        string
	Nonce        string
	CodeVerifier string
}

func NewCookie(name, value string, expiresIn time.Duration) Cookie {
	return Cookie{
		name:      name,
		value:     value,
		expiresIn: expiresIn,
	}
}

func (h *Handler) getCallbackCookies(r *http.Request) (*CallbackCookies, error) {
	state, err := h.getEncryptedCookie(r, StateCookieName)
	if err != nil {
		return nil, err
	}

	nonce, err := h.getEncryptedCookie(r, NonceCookieName)
	if err != nil {
		return nil, err
	}

	codeVerifier, err := h.getEncryptedCookie(r, CodeVerifierCookieName)
	if err != nil {
		return nil, err
	}

	return &CallbackCookies{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
	}, nil
}

func (h *Handler) setEncryptedCookies(w http.ResponseWriter, cookies ...Cookie) error {
	for _, cookie := range cookies {
		err := h.setEncryptedCookie(w, cookie.name, cookie.value, cookie.expiresIn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) setEncryptedCookie(w http.ResponseWriter, key string, plaintext string, expiresIn time.Duration) error {
	ciphertext, err := h.Crypter.Encrypt([]byte(plaintext))
	if err != nil {
		return fmt.Errorf("unable to encrypt cookie '%s': %w", key, err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     key,
		Value:    base64.StdEncoding.EncodeToString(ciphertext),
		Expires:  time.Now().Add(expiresIn),
		Secure:   h.SecureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func (h *Handler) getEncryptedCookie(r *http.Request, key string) (string, error) {
	encoded, err := r.Cookie(key)
	if err != nil {
		return "", fmt.Errorf("no cookie named '%s': %w", key, err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded.Value)
	if err != nil {
		return "", fmt.Errorf("cookie named '%s' is not base64 encoded: %w", key, err)
	}

	plaintext, err := h.Crypter.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt cookie '%s': %w", key, err)
	}

	return string(plaintext), nil
}

func (h *Handler) deleteCookie(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:     key,
		Secure:   h.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}
