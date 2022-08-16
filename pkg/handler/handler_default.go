package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/handler/url"
	mw "github.com/nais/wonderwall/pkg/middleware"
)

// Default proxies all requests upstream.
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntry(r).WithField("request_path", r.URL.Path)
	isAuthenticated := false

	accessToken, ok := h.accessToken(w, r)
	if ok {
		// add authentication if session cookie and token checks out
		isAuthenticated = true

		// force new authentication if loginstatus is enabled and cookie isn't set
		if h.Loginstatus.NeedsLogin(r) {
			isAuthenticated = false
			logger.Info("default: loginstatus was enabled, but no matching cookie was found; state is now unauthenticated")
		}
	}

	if h.AutoLogin.NeedsLogin(r, isAuthenticated) {
		logger.Debug("default: auto-login is enabled; request does not match any configured ignorable paths")

		redirectTarget := r.URL.String()
		path := h.Path(r)

		loginUrl := url.LoginURL(path, redirectTarget)
		http.Redirect(w, r, loginUrl, http.StatusTemporaryRedirect)
		return
	}

	ctx := r.Context()

	if isAuthenticated {
		ctx = mw.WithAccessToken(ctx, accessToken)
	}

	h.ReverseProxy.ServeHTTP(w, r.WithContext(ctx))
}

func (h *Handler) accessToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	sessionData, err := h.getSessionFromCookie(w, r)
	if err != nil || sessionData == nil || len(sessionData.AccessToken) == 0 {
		return "", false
	}

	return sessionData.AccessToken, true
}
