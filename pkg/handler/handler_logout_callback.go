package handler

import (
	"net/http"

	logentry "github.com/nais/wonderwall/pkg/middleware"
)

// LogoutCallback handles the callback initiated by the self-initiated logout after single-logout at the identity provider.
func (h *Handler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	redirect := h.Client.LogoutCallback(r, h.Config.Ingress).PostLogoutRedirectURI()

	logentry.LogEntry(r).Debugf("logout/callback: redirecting to %s", redirect)
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}
