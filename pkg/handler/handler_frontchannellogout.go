package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/metrics"
	mw "github.com/nais/wonderwall/pkg/middleware"
)

// FrontChannelLogout performs a local logout initiated by a third party in the SSO circle-of-trust.
func (h *Handler) FrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	// Unconditionally destroy all local references to the session.
	cookie.Clear(w, cookie.Session, h.CookieOptsPathAware(r))

	if h.Loginstatus.Enabled() {
		h.Loginstatus.ClearCookie(w, h.CookieOptions)
	}

	logoutFrontchannel := h.Client.LogoutFrontchannel(r)
	if logoutFrontchannel.MissingSidParameter() {
		logger.Debug("front-channel logout: sid parameter not set in request; ignoring")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	sid := logoutFrontchannel.Sid()
	sessionData, err := h.Sessions.GetForID(r, sid)
	if err != nil {
		logger.Debugf("front-channel logout: could not get session (user might already be logged out): %+v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	err = h.Sessions.DestroyForID(r, sid)
	if err != nil {
		logger.Warnf("front-channel logout: destroying session: %+v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	} else if sessionData != nil {
		logger.WithField("jti", sessionData.IDTokenJwtID).Info("front-channel logout: successful logout")
	}

	metrics.ObserveLogout(metrics.LogoutOperationFrontChannel)
	w.WriteHeader(http.StatusOK)
}
