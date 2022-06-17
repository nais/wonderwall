package router

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-redis/redis/v8"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/session"
)

// localSessionID prefixes the given `sid` or `session_state` with the given client ID to prevent key collisions.
// `sid` or `session_state` is a key that refers to the user's unique SSO session at the Identity Provider, and the same key is present
// in all tokens acquired by any Relying Party (such as Wonderwall) during that session.
// Thus, we cannot assume that the value of `sid` or `session_state` to uniquely identify the pair of (user, application session)
// if using a shared session store.
func (h *Handler) localSessionID(sessionID string) string {
	return fmt.Sprintf("%s:%s:%s", h.Config.OpenID.Provider, h.Provider.GetClientConfiguration().GetClientID(), sessionID)
}

func (h *Handler) getSessionFromCookie(w http.ResponseWriter, r *http.Request) (*session.Data, error) {
	sessionID, err := cookie.GetDecrypted(r, cookie.Session, h.Crypter)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	sessionData, err := h.getSession(r.Context(), sessionID)
	if err == nil {
		h.DeleteSessionFallback(w, r)
		return sessionData, nil
	}

	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("session not found in store: %w", err)
	}

	log.Warnf("get session: store is unavailable: %+v; using cookie fallback", err)

	fallbackSessionData, err := h.GetSessionFallback(r)
	if err != nil {
		return nil, fmt.Errorf("getting fallback session: %w", err)
	}

	return fallbackSessionData, nil
}

func (h *Handler) getSession(ctx context.Context, sessionID string) (*session.Data, error) {
	encryptedSessionData, err := h.Sessions.Read(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("reading session data from store: %w", err)
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

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request, tokens *jwt.Tokens, rawTokens *oauth2.Token, params url.Values) error {
	externalSessionID, err := session.NewSessionID(h.Provider.GetOpenIDConfiguration(), tokens.IDToken, params)
	if err != nil {
		return fmt.Errorf("generating session ID: %w", err)
	}

	sessionLifetime := h.getSessionLifetime(rawTokens.Expiry)
	opts := h.CookieOptions.WithExpiresIn(sessionLifetime)

	sessionID := h.localSessionID(externalSessionID)
	err = cookie.EncryptAndSet(w, cookie.Session, sessionID, opts, h.Crypter)
	if err != nil {
		return fmt.Errorf("setting session cookie: %w", err)
	}

	sessionMetadata := session.NewMetadata(time.Now().Add(sessionLifetime))
	sessionData := session.NewData(externalSessionID, tokens, rawTokens.RefreshToken, sessionMetadata)

	encryptedSessionData, err := sessionData.Encrypt(h.Crypter)
	if err != nil {
		return fmt.Errorf("encrypting session data: %w", err)
	}

	err = h.Sessions.Write(r.Context(), sessionID, encryptedSessionData, sessionLifetime)
	if err == nil {
		h.DeleteSessionFallback(w, r)
		return nil
	}

	log.Warnf("create session: store is unavailable: %+v; using cookie fallback", err)

	err = h.SetSessionFallback(w, sessionData, sessionLifetime)
	if err != nil {
		return fmt.Errorf("writing session to fallback store: %w", err)
	}

	return nil
}

func (h *Handler) destroySession(w http.ResponseWriter, r *http.Request, sessionID string) error {
	err := h.Sessions.Delete(r.Context(), sessionID)
	if err != nil {
		return fmt.Errorf("deleting session from store: %w", err)
	}

	h.DeleteSessionFallback(w, r)
	return nil
}
