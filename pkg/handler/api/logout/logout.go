package logout

import (
	"errors"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
	errorhandler "github.com/nais/wonderwall/pkg/handler/error"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/metrics"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/session"
)

type Source interface {
	GetClient() *openidclient.Client
	GetCookieOptions() cookie.Options
	GetCookieOptsPathAware(r *http.Request) cookie.Options
	GetErrorHandler() errorhandler.Handler
	GetLoginstatus() *loginstatus.Loginstatus
	GetSessions() *session.Handler
}

func Handler(src Source, w http.ResponseWriter, r *http.Request) {
	logger := logentry.LogEntryFrom(r)
	logout, err := src.GetClient().Logout(r)
	if err != nil {
		src.GetErrorHandler().InternalError(w, r, err)
		return
	}

	idToken := ""

	sessionData, err := src.GetSessions().Get(r)
	if err == nil && sessionData != nil {
		idToken = sessionData.IDToken

		err = src.GetSessions().DestroyForID(r, sessionData.ExternalSessionID)
		if err != nil && !errors.Is(err, session.KeyNotFoundError) {
			src.GetErrorHandler().InternalError(w, r, fmt.Errorf("logout: destroying session: %w", err))
			return
		}

		fields := log.Fields{
			"jti": sessionData.IDTokenJwtID,
		}
		logger.WithFields(fields).Info("logout: successful local logout")
	}

	cookie.Clear(w, cookie.Session, src.GetCookieOptsPathAware(r))

	if src.GetLoginstatus().Enabled() {
		src.GetLoginstatus().ClearCookie(w, src.GetCookieOptions())
	}

	logger.Debug("logout: redirecting to identity provider")
	metrics.ObserveLogout(metrics.LogoutOperationSelfInitiated)
	http.Redirect(w, r, logout.SingleLogoutURL(idToken), http.StatusTemporaryRedirect)
}
