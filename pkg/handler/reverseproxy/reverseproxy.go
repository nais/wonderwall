package reverseproxy

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/handler/autologin"
	"github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/loginstatus"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

type Source interface {
	GetAutoLogin() *autologin.AutoLogin
	GetLoginstatus() *loginstatus.Loginstatus
	GetPath(r *http.Request) string
	GetSessions() *session.Handler
}

type ReverseProxy struct {
	*httputil.ReverseProxy
}

func New(upstreamHost string) *ReverseProxy {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// Instruct http.ReverseProxy to not modify X-Forwarded-For header
			r.Header["X-Forwarded-For"] = nil
			// Request should go to correct host
			r.URL.Host = upstreamHost
			r.URL.Scheme = "http"

			accessToken, ok := mw.AccessTokenFrom(r.Context())
			if ok {
				r.Header.Set("authorization", "Bearer "+accessToken)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger := mw.LogEntryFrom(r)

			if errors.Is(err, context.Canceled) {
				w.WriteHeader(499)
			} else {
				logger.Warnf("reverseproxy: proxy error: %+v", err)
				w.WriteHeader(http.StatusBadGateway)
			}
		},
		ErrorLog: log.New(logrusErrorWriter{}, "reverseproxy: ", 0),
	}
	return &ReverseProxy{rp}
}

func (rp *ReverseProxy) Handler(src Source, w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)
	isAuthenticated := false

	accessToken, err := src.GetSessions().GetAccessToken(r)
	switch {
	case err == nil:
		// add authentication if session cookie and token checks out
		isAuthenticated = true

		// force new authentication if loginstatus is enabled and cookie isn't set
		if src.GetLoginstatus().NeedsLogin(r) {
			isAuthenticated = false
			logger.Info("default: loginstatus was enabled, but no matching cookie was found; state is now unauthenticated")
		}
	case errors.Is(err, session.ErrUnexpected):
		logger.Errorf("default: unauthenticated: %+v", err)
	case errors.Is(err, session.ErrInvalidState):
		logger.Warnf("default: unauthenticated: %+v", err)
	case errors.Is(err, session.ErrKeyNotFound):
		logger.Debug("default: unauthenticated: session not found")
	case errors.Is(err, session.ErrCookieNotFound):
		logger.Debug("default: unauthenticated: session cookie not found")
	default:
		logger.Infof("default: unauthenticated: %+v", err)
	}

	if src.GetAutoLogin().NeedsLogin(r, isAuthenticated) {
		redirectTarget := r.URL.String()
		path := src.GetPath(r)

		loginUrl := url.LoginURL(path, redirectTarget)
		fields := logrus.Fields{
			"redirect_after_login": redirectTarget,
			"redirect_to":          loginUrl,
		}

		logger.WithFields(fields).Info("default: unauthenticated: request matches auto-login; redirecting to login...")
		http.Redirect(w, r, loginUrl, http.StatusTemporaryRedirect)
		return
	}

	ctx := r.Context()

	if isAuthenticated {
		ctx = mw.WithAccessToken(ctx, accessToken)
	}

	rp.ServeHTTP(w, r.WithContext(ctx))
}

type logrusErrorWriter struct{}

func (w logrusErrorWriter) Write(p []byte) (n int, err error) {
	logrus.Warnf("%s", string(p))
	return len(p), nil
}
