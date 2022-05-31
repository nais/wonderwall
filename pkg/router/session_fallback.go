package router

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/session"
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

func (h *Handler) SessionFallbackRefreshTokenCookieName() string {
	return SessionCookieName + ".4"
}

func (h *Handler) SessionFallbackTimesToRefreshCookieName() string {
	return SessionCookieName + ".5"
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

	err = h.setEncryptedCookie(w, h.SessionFallbackRefreshTokenCookieName(), data.RefreshToken, opts)
	if err != nil {
		return fmt.Errorf("setting session refresh_token fallback cookie: %w", err)
	}

	timesToRefreshString := strconv.Itoa(int(data.TimesToRefresh))
	err = h.setEncryptedCookie(w, h.SessionFallbackTimesToRefreshCookieName(), timesToRefreshString, opts)
	if err != nil {
		return fmt.Errorf("setting session times to refresh fallback cookie: %w", err)
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

	refreshToken, err := h.getDecryptedCookie(r, h.SessionFallbackRefreshTokenCookieName())
	if err != nil {
		return nil, fmt.Errorf("reading refresh_token from fallback cookie: %w", err)
	}

	timesToRefreshString, err := h.getDecryptedCookie(r, h.SessionFallbackTimesToRefreshCookieName())
	if err != nil {
		return nil, fmt.Errorf("reading refresh times from fallback cookie: %w", err)
	}

	timesToRefreshInt, err := strconv.Atoi(timesToRefreshString)
	if err != nil {
		return nil, fmt.Errorf("converting refresh times from string: %w", err)
	}

	jwkSet, err := h.Provider.GetPublicJwkSet(r.Context())
	if err != nil {
		return nil, fmt.Errorf("callback: getting jwks: %w", err)
	}

	tokens, err := jwt.ParseTokensFromStrings(idToken, accessToken, refreshToken, *jwkSet)
	if err != nil {
		// JWKS might not be up-to-date, so we'll want to force a refresh for the next attempt
		_, _ = h.Provider.RefreshPublicJwkSet(r.Context())
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}

	return session.NewData(externalSessionID, tokens, int64(timesToRefreshInt)), nil
}

func (h *Handler) DeleteSessionFallback(w http.ResponseWriter, r *http.Request) {
	deleteIfNotFound := func(h *Handler, w http.ResponseWriter, cookieName string) {
		if r == nil {
			return
		}
		_, err := r.Cookie(cookieName)
		if errors.Is(err, http.ErrNoCookie) {
			return
		}

		h.deleteCookie(w, cookieName, h.CookieOptions)
	}

	deleteIfNotFound(h, w, h.SessionFallbackAccessTokenCookieName())
	deleteIfNotFound(h, w, h.SessionFallbackExternalIDCookieName())
	deleteIfNotFound(h, w, h.SessionFallbackIDTokenCookieName())
	deleteIfNotFound(h, w, h.SessionFallbackRefreshTokenCookieName())
	deleteIfNotFound(h, w, h.SessionFallbackTimesToRefreshCookieName())
}
