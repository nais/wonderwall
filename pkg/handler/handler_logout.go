package handler

import (
	"errors"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/metrics"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

// Logout triggers self-initiated logout for the current user.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	logger := logentry.LogEntry(r)

	var idToken string

	sessionData, err := h.getSessionFromCookie(w, r)
	if err == nil && sessionData != nil {
		idToken = sessionData.IDToken

		err = h.destroySession(w, r, h.localSessionID(sessionData.ExternalSessionID))
		if err != nil && !errors.Is(err, session.KeyNotFoundError) {
			h.InternalError(w, r, fmt.Errorf("logout: destroying session: %w", err))
			return
		}

		fields := log.Fields{
			"jti": sessionData.IDTokenJwtID,
		}
		logger.WithFields(fields).Info("logout: successful local logout")
	}

	cookie.Clear(w, cookie.Session, h.CookieOptions)

	if h.Loginstatus.Enabled() {
		h.Loginstatus.ClearCookie(w, h.CookieOptions)
	}

	logger.Debug("logout: redirecting to identity provider")
	metrics.ObserveLogout(metrics.LogoutOperationSelfInitiated)
	http.Redirect(w, r, h.Client.Logout().SingleLogoutURL(idToken), http.StatusTemporaryRedirect)
}
