package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	logentry "github.com/nais/wonderwall/pkg/middleware"
)

// FrontChannelLogout triggers logout triggered by a third-party.
func (h *Handler) FrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	// Unconditionally destroy all local references to the session.
	cookie.Clear(w, cookie.Session, h.CookieOptions)

	if h.Cfg.Wonderwall().Loginstatus.Enabled {
		h.Loginstatus.ClearCookie(w, h.CookieOptions)
	}

	logoutFrontchannel := h.Client.LogoutFrontchannel(r)
	if logoutFrontchannel.MissingSidParameter() {
		logentry.LogEntry(r).Info("front-channel logout: sid parameter not set in request; ignoring")
		h.DeleteSessionFallback(w, r)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	sid := logoutFrontchannel.Sid()
	sessionID := h.localSessionID(sid)
	sessionData, err := h.getSession(r, sessionID)
	if err != nil {
		logentry.LogEntry(r).Infof("front-channel logout: getting session (user might already be logged out): %+v", err)
	}

	err = h.destroySession(w, r, sessionID)
	if err != nil {
		logentry.LogEntry(r).Warnf("front-channel logout: destroying session: %+v", err)
	} else if sessionData != nil {
		logentry.LogEntry(r).WithField("jti", sessionData.IDTokenJwtID).Infof("front-channel logout: successful logout")
	}

	w.WriteHeader(http.StatusOK)
}
