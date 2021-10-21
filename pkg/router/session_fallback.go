package router

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/session"
)

func (h *Handler) SessionFallbackExternalIDCookieName() string {
	return h.GetSessionCookieName() + ".1"
}

func (h *Handler) SessionFallbackIDTokenCookieName() string {
	return h.GetSessionCookieName() + ".2"
}

func (h *Handler) SessionFallbackAccessTokenCookieName() string {
	return h.GetSessionCookieName() + ".3"
}

func (h *Handler) SetSessionFallback(w http.ResponseWriter, data *session.Data, expiresIn time.Duration) error {
	err := h.setEncryptedCookie(w, h.SessionFallbackExternalIDCookieName(), data.ExternalSessionID, expiresIn)
	if err != nil {
		return fmt.Errorf("setting session id fallback cookie: %w", err)
	}

	err = h.setEncryptedCookie(w, h.SessionFallbackAccessTokenCookieName(), data.AccessToken, expiresIn)
	if err != nil {
		return fmt.Errorf("setting session id_token fallback cookie: %w", err)
	}

	err = h.setEncryptedCookie(w, h.SessionFallbackIDTokenCookieName(), data.IDToken, expiresIn)
	if err != nil {
		return fmt.Errorf("setting session access_token fallback cookie: %w", err)
	}

	return nil
}

func (h *Handler) GetSessionFallback(r *http.Request) (*session.Data, error) {
	externalSessionID, err := h.getEncryptedCookie(r, h.SessionFallbackExternalIDCookieName())
	if err != nil {
		return nil, fmt.Errorf("reading session ID from fallback cookie: %w", err)
	}

	idToken, err := h.getEncryptedCookie(r, h.SessionFallbackIDTokenCookieName())
	if err != nil {
		return nil, fmt.Errorf("reading id_token from fallback cookie: %w", err)
	}

	accessToken, err := h.getEncryptedCookie(r, h.SessionFallbackAccessTokenCookieName())
	if err != nil {
		return nil, fmt.Errorf("reading access_token from fallback cookie: %w", err)
	}

	return session.NewData(externalSessionID, accessToken, idToken), nil
}

func (h *Handler) DeleteSessionFallback(w http.ResponseWriter, r *http.Request) {
	deleteIfNotFound := func(h *Handler, w http.ResponseWriter, cookieName string) {
		_, err := r.Cookie(cookieName)
		if errors.Is(err, http.ErrNoCookie) {
			return
		}

		h.deleteCookie(w, cookieName)
	}

	deleteIfNotFound(h, w, h.SessionFallbackAccessTokenCookieName())
	deleteIfNotFound(h, w, h.SessionFallbackExternalIDCookieName())
	deleteIfNotFound(h, w, h.SessionFallbackIDTokenCookieName())
}
