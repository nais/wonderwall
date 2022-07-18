package handler

import (
	"net/http"

	logentry "github.com/nais/wonderwall/pkg/middleware"
)

// LogoutCallback handles the callback from the self-initiated logout for the current user
func (h *Handler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	redirect := h.Client.LogoutCallback(r).PostLogoutRedirectURI()

	logentry.LogEntry(r).Infof("logout/callback: redirecting to %s", redirect)
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}
