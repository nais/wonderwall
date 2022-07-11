package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/openid"
	logentry "github.com/nais/wonderwall/pkg/router/middleware"
)

const (
	LogoutCookieLifetime = 5 * time.Minute
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
			"claims": sessionData.Claims,
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
	}

	err = h.setLogoutCookie(w, logout.Cookie())
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("logout: setting logout cookie: %w", err))
		return
	}

	fields := map[string]interface{}{
		"redirect_to": logout.CanonicalRedirect(),
	}
	logger := logentry.LogEntryWithFields(r.Context(), fields)
	logger.Info().Msg("logout: redirecting to identity provider")

	http.Redirect(w, r, logout.SingleLogoutURL(idToken), http.StatusTemporaryRedirect)
}

func (h *Handler) setLogoutCookie(w http.ResponseWriter, logoutCookie *openid.LogoutCookie) error {
	logoutCookieJson, err := json.Marshal(logoutCookie)
	if err != nil {
		return fmt.Errorf("marshalling login cookie: %w", err)
	}

	opts := h.CookieOptions.WithExpiresIn(LogoutCookieLifetime)
	value := string(logoutCookieJson)

	return cookie.EncryptAndSet(w, cookie.Logout, value, opts, h.Crypter)
}
