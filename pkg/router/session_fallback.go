package router

import (
	"fmt"
	"github.com/nais/wonderwall/pkg/session"
	"net/http"
	"time"
)

func (h *Handler) SessionFallbackExternalIDCookieName() string {
	return h.GetSessionCookieName() + ".eid"
}

func (h *Handler) SessionFallbackIDTokenCookieName() string {
	return h.GetSessionCookieName() + ".id_token"
}

func (h *Handler) SessionFallbackAccessTokenCookieName() string {
	return h.GetSessionCookieName() + ".access_token"
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

func (h *Handler) DeleteSessionFallback(w http.ResponseWriter) {
	h.deleteCookie(w, h.SessionFallbackAccessTokenCookieName())
	h.deleteCookie(w, h.SessionFallbackExternalIDCookieName())
	h.deleteCookie(w, h.SessionFallbackIDTokenCookieName())
}
