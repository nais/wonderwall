package router

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	LoginCookieLifetime = 10 * time.Minute

	SessionCookieNameTemplate = "io.nais.wonderwall.session"
	LoginCookieNameTemplate   = "io.nais.wonderwall.callback"
)

type Cookie struct {
	name      string
	value     string
	expiresIn time.Duration
}

type LoginCookie struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	Referer      string `json:"referer"`
}

func (h *Handler) GetLoginCookieName() string {
	return LoginCookieNameTemplate
}

func (h *Handler) GetSessionCookieName() string {
	return SessionCookieNameTemplate
}

func (h *Handler) getLoginCookie(w http.ResponseWriter, r *http.Request) (*LoginCookie, error) {
	loginCookieJson, err := h.getEncryptedCookie(r, h.GetLoginCookieName())
	if err != nil {
		return nil, err
	}

	var loginCookie LoginCookie
	err = json.Unmarshal([]byte(loginCookieJson), &loginCookie)
	if err != nil {
		return nil, err
	}

	// delete cookie as we no longer need it
	h.deleteCookie(w, h.GetLoginCookieName())

	return &loginCookie, nil
}

func (h *Handler) setLoginCookie(w http.ResponseWriter, loginCookie *LoginCookie) error {
	loginCookieJson, err := json.Marshal(loginCookie)
	if err != nil {
		return fmt.Errorf("marshalling login cookie: %w", err)
	}

	err = h.setEncryptedCookie(w, h.GetLoginCookieName(), string(loginCookieJson), LoginCookieLifetime)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) setEncryptedCookie(w http.ResponseWriter, key string, plaintext string, expiresIn time.Duration) error {
	ciphertext, err := h.Crypter.Encrypt([]byte(plaintext))
	if err != nil {
		return fmt.Errorf("unable to encrypt cookie '%s': %w", key, err)
	}

	http.SetCookie(w, &http.Cookie{
		Expires:  time.Now().Add(expiresIn),
		HttpOnly: true,
		MaxAge:   int(expiresIn.Seconds()),
		Name:     key,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   h.SecureCookies,
		Value:    base64.StdEncoding.EncodeToString(ciphertext),
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
	expires := time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Expires:  expires,
		HttpOnly: true,
		MaxAge:   -1,
		Name:     key,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   h.SecureCookies,
	})
}
