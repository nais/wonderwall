package router

import (
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
)

type session struct {
	id    string
	token *oauth2.Token
}

func (h *Handler) storeSession(key string, session session) {
	session.id = key
	h.lock.Lock()
	h.sessions[key] = session
	h.lock.Unlock()
}

func (h *Handler) deleteSession(key string) {
	h.lock.Lock()
	delete(h.sessions, key)
	h.lock.Unlock()
}

func (h *Handler) getSessionFromCookie(r *http.Request) (*session, error) {
	sessionID, err := h.getEncryptedCookie(r, SessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	session, ok := h.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("no token stored for session %s", sessionID)
	}

	return &session, nil
}
