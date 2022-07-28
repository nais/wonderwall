package handler

import (
	"context"
	"net/http"

	logentry "github.com/nais/wonderwall/pkg/middleware"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

// Default proxies all requests upstream.
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	logger := logentry.LogEntry(r).WithField("request_path", r.URL.Path)
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
		loginUrl := urlpkg.LoginURL(h.Path(), redirectTarget)

		http.Redirect(w, r, loginUrl, http.StatusTemporaryRedirect)
		return
	}

	ctx := r.Context()

	if isAuthenticated {
		ctx = withAccessToken(ctx, accessToken)
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

type contextKey string

const (
	ctxAccessToken = contextKey("AccessToken")
)

func accessTokenFrom(ctx context.Context) (string, bool) {
	accessToken, ok := ctx.Value(ctxAccessToken).(string)
	return accessToken, ok
}

func withAccessToken(ctx context.Context, accessToken string) context.Context {
	return context.WithValue(ctx, ctxAccessToken, accessToken)
}
