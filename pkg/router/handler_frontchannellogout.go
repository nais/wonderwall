package router

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// FrontChannelLogout triggers logout triggered by a third-party.
func (h *Handler) FrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	sid := params.Get("sid")

	if len(sid) == 0 {
		h.BadRequest(w, r, fmt.Errorf("front-channel logout: sid not set in query parameter"))
		return
	}

	sessionID := h.localSessionID(sid)

	err := h.destroySession(w, r, sessionID)
	if err != nil {
		log.Error(err)
		// Session is already destroyed at the OP and is highly unlikely to be used again.
	}

	// Unconditionally destroy all local references to the session.
	h.deleteCookie(w, h.GetSessionCookieName())
	w.WriteHeader(http.StatusOK)
}
