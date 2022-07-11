package router

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/openid"
	logentry "github.com/nais/wonderwall/pkg/router/middleware"
)

// LogoutCallback handles the callback from the self-initiated logout for the current user
func (h *Handler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	cookie.Clear(w, cookie.Logout, h.CookieOptions)

	logger := logentry.LogEntry(r.Context())

	logoutCookie, err := h.getLogoutCookie(r)
	if err != nil {
		logger.Warn().Msgf("logout/callback: getting cookie: %+v", err)
		http.Redirect(w, r, h.Cfg.Wonderwall().Ingress, http.StatusTemporaryRedirect)
		return
	}

	logoutCallback := h.Client.LogoutCallback(r, logoutCookie)
	if err := logoutCallback.ValidateRequest(); err != nil {
		logger.Warn().Msgf("logout/callback: %+v; falling back to ingress", err)
		http.Redirect(w, r, h.Cfg.Wonderwall().Ingress, http.StatusTemporaryRedirect)
		return
	}

	logger.Info().Msgf("logout/callback: redirecting to %s", logoutCookie.RedirectTo)
	http.Redirect(w, r, logoutCookie.RedirectTo, http.StatusTemporaryRedirect)
}

func (h *Handler) getLogoutCookie(r *http.Request) (*openid.LogoutCookie, error) {
	logoutCookieJson, err := cookie.GetDecrypted(r, cookie.Logout, h.Crypter)
	if err != nil {
		return nil, err
	}

	var logoutCookie openid.LogoutCookie
	err = json.Unmarshal([]byte(logoutCookieJson), &logoutCookie)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling: %w", err)
	}

	return &logoutCookie, nil
}
