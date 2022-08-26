package handler

import (
	"errors"
	"net/http"

	"github.com/nais/wonderwall/pkg/handler/url"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

// Default proxies all requests upstream.
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r).WithField("request_path", r.URL.Path)
	isAuthenticated := false

	accessToken, err := h.Sessions.GetAccessToken(r)
	if err == nil {
		// add authentication if session cookie and token checks out
		isAuthenticated = true

		// force new authentication if loginstatus is enabled and cookie isn't set
		if h.Loginstatus.NeedsLogin(r) {
			isAuthenticated = false
			logger.Info("default: loginstatus was enabled, but no matching cookie was found; state is now unauthenticated")
		}
	} else if errors.Is(err, session.UnexpectedError) {
		logger.Errorf("default: getting session: %+v", err)
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
