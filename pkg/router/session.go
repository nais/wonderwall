package router

import (
	"fmt"
	"github.com/nais/wonderwall/pkg/session"
	"net/http"
)

func (h *Handler) getSessionFromCookie(r *http.Request) (*session.Data, error) {
	sessionID, err := h.getEncryptedCookie(r, h.GetSessionCookieName())
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	return h.Sessions.Read(r.Context(), sessionID)
}
