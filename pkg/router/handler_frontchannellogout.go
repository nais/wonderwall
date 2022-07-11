package router

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
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
		log.Info("front-channel logout: sid parameter not set in request; ignoring")
		h.DeleteSessionFallback(w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	sid := logoutFrontchannel.Sid()
	sessionID := h.localSessionID(sid)
	sessionData, err := h.getSession(r.Context(), sessionID)
	if err != nil {
		log.Infof("front-channel logout: getting session (user might already be logged out): %+v", err)
	}

	err = h.destroySession(w, r, sessionID)
	if err != nil {
		log.Errorf("front-channel logout: destroying session: %+v", err)
	} else if sessionData != nil {
		log.WithField("claims", sessionData.Claims).Infof("front-channel logout: successful logout")
	}

	w.WriteHeader(http.StatusOK)
}
