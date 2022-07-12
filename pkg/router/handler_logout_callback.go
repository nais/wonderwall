package router

import (
	"net/http"

	logentry "github.com/nais/wonderwall/pkg/router/middleware"
)

// LogoutCallback handles the callback from the self-initiated logout for the current user
func (h *Handler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	redirect := h.Client.LogoutCallback(r).PostLogoutRedirectURI()

	logger := logentry.LogEntry(r.Context())
	logger.Info().Msgf("logout/callback: redirecting to %s", redirect)
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}
