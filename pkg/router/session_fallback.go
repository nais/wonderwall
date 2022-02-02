package router

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/token"
)

func (h *Handler) SessionFallbackExternalIDCookieName() string {
	return SessionCookieName + ".1"
}

func (h *Handler) SessionFallbackIDTokenCookieName() string {
	return SessionCookieName + ".2"
}

func (h *Handler) SessionFallbackAccessTokenCookieName() string {
	return SessionCookieName + ".3"
}

func (h *Handler) SetSessionFallback(w http.ResponseWriter, data *session.Data, expiresIn time.Duration) error {
	opts := h.CookieOptions.WithExpiresIn(expiresIn)

	err := h.setEncryptedCookie(w, h.SessionFallbackExternalIDCookieName(), data.ExternalSessionID, opts)
	if err != nil {
		return fmt.Errorf("setting session id fallback cookie: %w", err)
	}

	err = h.setEncryptedCookie(w, h.SessionFallbackAccessTokenCookieName(), data.AccessToken, opts)
	if err != nil {
		return fmt.Errorf("setting session id_token fallback cookie: %w", err)
	}

	err = h.setEncryptedCookie(w, h.SessionFallbackIDTokenCookieName(), data.IDToken, opts)
	if err != nil {
		return fmt.Errorf("setting session access_token fallback cookie: %w", err)
	}

	return nil
}

func (h *Handler) GetSessionFallback(r *http.Request) (*session.Data, error) {
	externalSessionID, err := h.getDecryptedCookie(r, h.SessionFallbackExternalIDCookieName())
	if err != nil {
		return nil, fmt.Errorf("reading session ID from fallback cookie: %w", err)
	}

	idToken, err := h.getDecryptedCookie(r, h.SessionFallbackIDTokenCookieName())
	if err != nil {
		return nil, fmt.Errorf("reading id_token from fallback cookie: %w", err)
	}

	accessToken, err := h.getDecryptedCookie(r, h.SessionFallbackAccessTokenCookieName())
	if err != nil {
		return nil, fmt.Errorf("reading access_token from fallback cookie: %w", err)
	}

	jwkSet := h.Provider.GetPublicJwkSet()
	tokens, err := token.ParseTokensFromStrings(idToken, accessToken, *jwkSet)
	if err != nil {
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}

	return session.NewData(externalSessionID, tokens), nil
}

func (h *Handler) DeleteSessionFallback(w http.ResponseWriter, r *http.Request) {
	deleteIfNotFound := func(h *Handler, w http.ResponseWriter, cookieName string) {
		_, err := r.Cookie(cookieName)
		if errors.Is(err, http.ErrNoCookie) {
			return
		}

		h.deleteCookie(w, cookieName, h.CookieOptions)
	}

	deleteIfNotFound(h, w, h.SessionFallbackAccessTokenCookieName())
	deleteIfNotFound(h, w, h.SessionFallbackExternalIDCookieName())
	deleteIfNotFound(h, w, h.SessionFallbackIDTokenCookieName())
}
