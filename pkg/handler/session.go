package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sethvargo/go-retry"

	"github.com/nais/wonderwall/pkg/cookie"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	retrypkg "github.com/nais/wonderwall/pkg/retry"
	"github.com/nais/wonderwall/pkg/session"
)

// localSessionID prefixes the given `sid` or `session_state` with the given client ID to prevent key collisions.
// `sid` or `session_state` is a key that refers to the user's unique SSO session at the Identity Provider, and the same key is present
// in all tokens acquired by any Relying Party (such as Wonderwall) during that session.
// Thus, we cannot assume that the value of `sid` or `session_state` to uniquely identify the pair of (user, application session)
// if using a shared session store.
func (h *Handler) localSessionID(sessionID string) string {
	return fmt.Sprintf("%s:%s:%s", h.OpenIDConfig.Provider().Name(), h.OpenIDConfig.Client().ClientID(), sessionID)
}

func (h *Handler) getSessionFromCookie(w http.ResponseWriter, r *http.Request) (*session.Data, error) {
	sessionID, err := cookie.GetDecrypted(r, cookie.Session, h.Crypter)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	sessionData, err := h.getSession(r, sessionID)
	if err == nil {
		h.DeleteSessionFallback(w, r)
		return sessionData, nil
	}

	if errors.Is(err, session.KeyNotFoundError) {
		return nil, fmt.Errorf("session not found in store: %w", err)
	}

	logentry.LogEntry(r).Warnf("get session: store is unavailable: %+v; using cookie fallback", err)

	fallbackSessionData, err := h.GetSessionFallback(w, r)
	if err != nil {
		return nil, fmt.Errorf("getting fallback session: %w", err)
	}

	return fallbackSessionData, nil
}

func (h *Handler) getSession(r *http.Request, sessionID string) (*session.Data, error) {
	var encryptedSessionData *session.EncryptedData
	var err error

	retryable := func(ctx context.Context) error {
		encryptedSessionData, err = h.Sessions.Read(ctx, sessionID)
		if err == nil {
			return nil
		}

		err = fmt.Errorf("reading session data from store: %w", err)
		if errors.Is(err, session.KeyNotFoundError) {
			return err
		}

		return retry.RetryableError(err)
	}

	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err != nil {
		return nil, err
	}

	sessionData, err := encryptedSessionData.Decrypt(h.Crypter)
	if err != nil {
		return nil, fmt.Errorf("decrypting session data: %w", err)
	}

	return sessionData, nil
}

func (h *Handler) getSessionLifetime(tokenExpiry time.Time) time.Duration {
	defaultSessionLifetime := h.Config.SessionMaxLifetime

	tokenDuration := tokenExpiry.Sub(time.Now())

	if tokenDuration <= defaultSessionLifetime {
		return tokenDuration
	}

	return defaultSessionLifetime
}

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request, tokens *openid.Tokens) error {
	params := r.URL.Query()

	externalSessionID, err := session.NewSessionID(h.OpenIDConfig.Provider(), tokens.IDToken, params)
	if err != nil {
		return fmt.Errorf("generating session ID: %w", err)
	}

	sessionLifetime := h.getSessionLifetime(tokens.Expiry)
	opts := h.CookieOptions.WithExpiresIn(sessionLifetime)

	sessionID := h.localSessionID(externalSessionID)
	err = cookie.EncryptAndSet(w, cookie.Session, sessionID, opts, h.Crypter)
	if err != nil {
		return fmt.Errorf("setting session cookie: %w", err)
	}

	sessionMetadata := session.NewMetadata(time.Now().Add(sessionLifetime))
	sessionData := session.NewData(externalSessionID, tokens, sessionMetadata)

	encryptedSessionData, err := sessionData.Encrypt(h.Crypter)
	if err != nil {
		return fmt.Errorf("encrypting session data: %w", err)
	}

	retryable := func(ctx context.Context) error {
		err = h.Sessions.Write(r.Context(), sessionID, encryptedSessionData, sessionLifetime)
		if err != nil {
			return retry.RetryableError(err)
		}

		return nil
	}

	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err == nil {
		h.DeleteSessionFallback(w, r)
		return nil
	}

	logentry.LogEntry(r).Warnf("create session: store is unavailable: %+v; using cookie fallback", err)

	err = h.SetSessionFallback(w, r, sessionData, sessionLifetime)
	if err != nil {
		return fmt.Errorf("writing session to fallback store: %w", err)
	}

	return nil
}

func (h *Handler) destroySession(w http.ResponseWriter, r *http.Request, sessionID string) error {
	retryable := func(ctx context.Context) error {
		err := h.Sessions.Delete(r.Context(), sessionID)
		if err == nil {
			return nil
		}

		err = fmt.Errorf("deleting session from store: %w", err)
		if errors.Is(err, session.KeyNotFoundError) {
			return err
		}

		return retry.RetryableError(err)
	}

	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err != nil {
		return err
	}

	h.DeleteSessionFallback(w, r)
	return nil
}
