package router

import (
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/token"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

// localSessionID prefixes the given `sid` with the given client ID to prevent key collisions.
// `sid` is a key that refers to the user's unique SSO session at the Identity Provider, and the same key is present
// in all tokens acquired by any Relying Party (such as Wonderwall) during that session.
// Thus, we cannot assume that the value of `sid` to uniquely identify the pair of (user, application session)
// if using a shared session store.
func (h *Handler) localSessionID(sid string) string {
	return fmt.Sprintf("%s-%s", h.Config.ClientID, sid)
}

func (h *Handler) getSessionFromCookie(r *http.Request) (*session.Data, error) {
	sessionID, err := h.getEncryptedCookie(r, h.GetSessionCookieName())
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	encryptedSessionData, err := h.Sessions.Read(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("session not found in store: %w", err)
		}

		fallbackSessionData, err := h.GetSessionFallback(r)
		if err != nil {
			return nil, fmt.Errorf("fallback session not found: %w", err)
		}

		return fallbackSessionData, nil
	}

	sessionData, err := encryptedSessionData.Decrypt(h.Crypter)
	if err != nil {
		return nil, fmt.Errorf("decrypting session data: %w", err)
	}

	return sessionData, nil
}

func (h *Handler) getSessionLifetime(accessToken string) (time.Duration, error) {
	defaultSessionLifetime := h.Config.SessionMaxLifetime

	tok, err := jwt.Parse([]byte(accessToken))
	if err != nil {
		return 0, err
	}

	tokenDuration := tok.Expiration().Sub(time.Now())

	if tokenDuration <= defaultSessionLifetime {
		return tokenDuration, nil
	}

	return defaultSessionLifetime, nil
}

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request, externalSessionID string, tokens *oauth2.Token, idToken *token.IDToken) error {
	sessionID := h.localSessionID(externalSessionID)

	sessionLifetime, err := h.getSessionLifetime(tokens.AccessToken)
	if err != nil {
		return fmt.Errorf("getting access token lifetime: %w", err)
	}

	err = h.setEncryptedCookie(w, h.GetSessionCookieName(), sessionID, sessionLifetime)
	if err != nil {
		return fmt.Errorf("setting session cookie: %w", err)
	}

	sessionData := session.NewData(externalSessionID, tokens.AccessToken, idToken.Raw)

	encryptedSessionData, err := sessionData.Encrypt(h.Crypter)
	if err != nil {
		return fmt.Errorf("encrypting session data: %w", err)
	}

	err = h.Sessions.Write(r.Context(), sessionID, encryptedSessionData, sessionLifetime)
	if err == nil {
		return nil
	}

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

	h.DeleteSessionFallback(w)
	return nil
}
