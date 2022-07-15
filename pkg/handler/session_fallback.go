package handler

import (
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/session"
)

func (h *Handler) SetSessionFallback(w http.ResponseWriter, r *http.Request, data *session.Data, expiresIn time.Duration) error {
	store := h.cookieStore(w, r)
	return store.Write(data, expiresIn)
}

func (h *Handler) GetSessionFallback(w http.ResponseWriter, r *http.Request) (*session.Data, error) {
	store := h.cookieStore(w, r)
	return store.Read(r.Context())
}

func (h *Handler) DeleteSessionFallback(w http.ResponseWriter, r *http.Request) {
	store := h.cookieStore(w, r)
	store.Delete()
}

func (h *Handler) cookieStore(w http.ResponseWriter, r *http.Request) session.CookieStore {
	return session.NewCookie(w, r, h.Crypter, h.Provider, h.CookieOptions)
}
