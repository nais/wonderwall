package router

import (
	"golang.org/x/oauth2"
)

func (h *Handler) storeSession(key string, token *oauth2.Token) {
	h.lock.Lock()
	h.sessions[key] = token
	h.lock.Unlock()
}

func (h *Handler) deleteSession(key string) {
	h.lock.Lock()
	delete(h.sessions, key)
	h.lock.Unlock()
}
