package handler

import (
	"net/http"
	"net/http/httputil"

	logentry "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

// Default proxies all requests upstream
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	isAuthenticated := false

	sessionData, err := h.getSessionFromCookie(w, r)

	hasSessionData := err == nil && sessionData != nil
	hasAccessToken := hasSessionData && len(sessionData.AccessToken) > 0
	if hasAccessToken {
		// add authentication if session cookie and token checks out
		isAuthenticated = true
	}

	// force new authentication if loginstatus is enabled and cookie isn't set
	if h.Loginstatus.NeedsLogin(r) {
		isAuthenticated = false
		logentry.LogEntry(r).Info("default: loginstatus was enabled, but no matching cookie was found; state is now unauthenticated")
	}

	if h.AutoLogin.NeedsLogin(r, isAuthenticated) {
		r.Header.Add("Referer", r.URL.String())
		h.Login(w, r)
		return
	}

	director := func(upstreamRequest *http.Request) {
		modifyRequest(upstreamRequest, r, h.Cfg.Wonderwall().UpstreamHost)

		if isAuthenticated {
			withAuthentication(upstreamRequest, sessionData)
		}
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(err.Error()))
	}

	reverseProxy := httputil.ReverseProxy{
		Director:     director,
		ErrorHandler: errorHandler,
	}
	reverseProxy.ServeHTTP(w, r)
}

func modifyRequest(dst, src *http.Request, upstreamHost string) {
	// Delete incoming authentication
	dst.Header.Del("authorization")
	// Instruct http.ReverseProxy to not modify X-Forwarded-For header
	dst.Header["X-Forwarded-For"] = nil
	// Request should go to correct host
	dst.Host = src.Host
	dst.URL.Host = upstreamHost
	dst.URL.Scheme = "http"
}

func withAuthentication(dst *http.Request, sessionData *session.Data) {
	dst.Header.Add("authorization", "Bearer "+sessionData.AccessToken)
}
