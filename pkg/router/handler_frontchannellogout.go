package router

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

// FrontChannelLogout triggers logout triggered by a third-party.
func (h *Handler) FrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	sid := params.Get("sid")

	// Unconditionally destroy all local references to the session.
	h.deleteCookie(w, SessionCookieName, h.CookieOptions)

	if h.Config.Features.Loginstatus.Enabled {
		h.Loginstatus.ClearCookie(w, h.CookieOptions)
	}

	if len(sid) == 0 {
		log.Info("sid parameter not set in request; ignoring")
		h.DeleteSessionFallback(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	sessionID := h.localSessionID(sid)
	sessionData, err := h.getSession(r.Context(), sessionID)
	if err != nil {
		log.Errorf("get session: %+v", err)
	}

	err = h.destroySession(w, r, sessionID)
	if err != nil {
		log.Errorf("destroying session: %+v", err)
		// Session is already destroyed at the OP and is highly unlikely to be used again.
	} else if sessionData != nil {
		log.WithField("claims", sessionData.Claims).Infof("successful front-channel logout")
	}

	w.WriteHeader(http.StatusOK)
}
