package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	errorhandler "github.com/nais/wonderwall/pkg/handler/error"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/metrics"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/session"
)

type LogoutSource interface {
	GetClient() *openidclient.Client
	GetCookieOptions() cookie.Options
	GetCookieOptsPathAware(r *http.Request) cookie.Options
	GetErrorHandler() errorhandler.Handler
	GetLoginstatus() *loginstatus.Loginstatus
	GetSessions() *session.Handler
}

type LogoutOptions struct {
	GlobalLogout bool
}

func Logout(src LogoutSource, w http.ResponseWriter, r *http.Request, opts LogoutOptions) {
	logger := logentry.LogEntryFrom(r)
	logout, err := src.GetClient().Logout(r)
	if err != nil {
		src.GetErrorHandler().InternalError(w, r, err)
		return
	}

	var idToken string

	sessions := src.GetSessions()

	key, err := sessions.GetKey(r)
	if err == nil {
		sessionData, err := sessions.Get(r, key)
		if err == nil && sessionData != nil {
			idToken = sessionData.IDToken

			err = sessions.Destroy(r, key)
			if err != nil && !errors.Is(err, session.ErrKeyNotFound) {
				src.GetErrorHandler().InternalError(w, r, fmt.Errorf("logout: destroying session: %w", err))
				return
			}

			logger.WithField("jti", sessionData.IDTokenJwtID).
				Info("logout: successful local logout")
			metrics.ObserveLogout(metrics.LogoutOperationLocal)
		}
	}

	cookie.Clear(w, cookie.Session, src.GetCookieOptsPathAware(r))

	if src.GetLoginstatus().Enabled() {
		src.GetLoginstatus().ClearCookie(w, src.GetCookieOptions())
	}

	if opts.GlobalLogout {
		logger.Debug("logout: redirecting to identity provider for global/single-logout")
		metrics.ObserveLogout(metrics.LogoutOperationSelfInitiated)
		http.Redirect(w, r, logout.SingleLogoutURL(idToken), http.StatusTemporaryRedirect)
	}
}
