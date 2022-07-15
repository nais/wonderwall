package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-redis/redis/v8"

	"github.com/nais/wonderwall/pkg/cookie"
	logentry "github.com/nais/wonderwall/pkg/middleware"
)

// Logout triggers self-initiated for the current user
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var idToken string

	sessionData, err := h.getSessionFromCookie(w, r)
	if err == nil && sessionData != nil {
		idToken = sessionData.IDToken
		err = h.destroySession(w, r, h.localSessionID(sessionData.ExternalSessionID))
		if err != nil && !errors.Is(err, redis.Nil) {
			h.InternalError(w, r, fmt.Errorf("logout: destroying session: %w", err))
			return
		}

		fields := map[string]interface{}{
			"jti": sessionData.IDTokenJwtID,
		}
		logger := logentry.LogEntryWithFields(r.Context(), fields)
		logger.Info().Msg("logout: successful local logout")
	}

	cookie.Clear(w, cookie.Session, h.CookieOptions)

	if h.Cfg.Wonderwall().Loginstatus.Enabled {
		h.Loginstatus.ClearCookie(w, h.CookieOptions)
	}

	logout, err := h.Client.Logout()
	if err != nil {
		h.InternalError(w, r, err)
		return
	}

	logger := logentry.LogEntry(r.Context())
	logger.Info().Msg("logout: redirecting to identity provider")

	http.Redirect(w, r, logout.SingleLogoutURL(idToken), http.StatusTemporaryRedirect)
}
