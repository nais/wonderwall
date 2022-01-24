package router

import (
	log "github.com/sirupsen/logrus"
	"net/http"
)

// FrontChannelLogout triggers logout triggered by a third-party.
func (h *Handler) FrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	sessionParamKeys := []string{"sid", "session_state"}
	externalSessionID := extractExternalSessionID(r, sessionParamKeys)

	// Unconditionally destroy all local references to the session.
	h.deleteCookie(w, SessionCookieName, h.Cookies)

	if len(externalSessionID) == 0 {
		log.Infof("any of parameters %q not set in request; ignoring", sessionParamKeys)
		h.DeleteSessionFallback(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	sessionID := h.localSessionID(externalSessionID)

	err := h.destroySession(w, r, sessionID)
	if err != nil {
		log.Error(err)
		// Session is already destroyed at the OP and is highly unlikely to be used again.
	}

	w.WriteHeader(http.StatusOK)
}

func extractExternalSessionID(r *http.Request, paramKeys []string) string {
	params := r.URL.Query()
	var sessionId = ""
	for _, k := range paramKeys {
		sessionId = params.Get(k)
		if len(sessionId) != 0 {
			return sessionId
		}
	}
	return sessionId
}
