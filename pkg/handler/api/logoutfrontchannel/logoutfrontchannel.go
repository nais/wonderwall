package logoutfrontchannel

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/metrics"
	mw "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/session"
)

type Source interface {
	GetClient() *openidclient.Client
	GetCookieOptions() cookie.Options
	GetCookieOptsPathAware(r *http.Request) cookie.Options
	GetLoginstatus() *loginstatus.Loginstatus
	GetSessions() *session.Handler
}

func Handler(src Source, w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	// Unconditionally destroy all local references to the session.
	cookie.Clear(w, cookie.Session, src.GetCookieOptsPathAware(r))

	if src.GetLoginstatus().Enabled() {
		src.GetLoginstatus().ClearCookie(w, src.GetCookieOptions())
	}

	logoutFrontchannel := src.GetClient().LogoutFrontchannel(r)
	if logoutFrontchannel.MissingSidParameter() {
		logger.Debug("front-channel logout: sid parameter not set in request; ignoring")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	sid := logoutFrontchannel.Sid()
	sessionData, err := src.GetSessions().GetForID(r, sid)
	if err != nil {
		logger.Debugf("front-channel logout: could not get session (user might already be logged out): %+v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	err = src.GetSessions().DestroyForID(r, sid)
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
