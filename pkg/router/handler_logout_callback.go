package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/openid"
	logentry "github.com/nais/wonderwall/pkg/router/middleware"
)

const (
	LogoutCookieLifetime = 5 * time.Minute
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

	params := r.URL.Query()
	expectedState := logoutCookie.State
	actualState := params.Get("state")

	if expectedState != actualState {
		logger.Warn().Msgf("logout/callback: state parameter mismatch: expected %s, got %s; falling back to ingress", expectedState, actualState)
		http.Redirect(w, r, h.Cfg.Wonderwall().Ingress, http.StatusTemporaryRedirect)
		return
	}

	if len(logoutCookie.RedirectTo) == 0 {
		logger.Warn().Msgf("logout/callback: empty redirect; falling back to ingress")
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
