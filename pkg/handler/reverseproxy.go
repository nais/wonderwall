package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	urllib "net/url"

	"github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/handler/autologin"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/url"
)

type ReverseProxySource interface {
	GetAccessToken(r *http.Request) (string, error)
	GetAutoLogin() *autologin.AutoLogin
	GetPath(r *http.Request) string
}

type ReverseProxy struct {
	*httputil.ReverseProxy
}

func NewReverseProxy(upstream *urllib.URL, preserveInboundHostHeader bool) *ReverseProxy {
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// preserve inbound Forwarded and X-Forwarded-* headers that is stripped when using Rewrite
			r.Out.Header["Forwarded"] = r.In.Header["Forwarded"]
			r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
			r.Out.Header["X-Forwarded-Host"] = r.In.Header["X-Forwarded-Host"]
			r.Out.Header["X-Forwarded-Proto"] = r.In.Header["X-Forwarded-Proto"]
			r.SetURL(upstream)

			if preserveInboundHostHeader {
				// preserve the inbound request's Host header
				r.Out.Host = r.In.Host
			}

			accessToken, ok := mw.AccessTokenFrom(r.In.Context())
			if ok {
				r.Out.Header.Set("authorization", "Bearer "+accessToken)
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

func (rp *ReverseProxy) Handler(src ReverseProxySource, w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)
	isAuthenticated := false

	accessToken, err := src.GetAccessToken(r)
	switch {
	case err == nil:
		// add authentication if session cookie and token checks out
		isAuthenticated = true
	case errors.Is(err, context.Canceled):
		logger.Debugf("default: unauthenticated: %+v (client disconnected before we could respond)", err)
	case errors.Is(err, session.ErrInvalidExternal):
		logger.Warnf("default: unauthenticated: %+v", err)
	case errors.Is(err, session.ErrNotFound):
		logger.Debugf("default: unauthenticated: %+v", err)
	case errors.Is(err, session.ErrInvalid):
		logger.Infof("default: unauthenticated: %+v", err)
	default:
		logger.Errorf("default: unauthenticated: unexpected error: %+v", err)
	}

	if src.GetAutoLogin().NeedsLogin(r, isAuthenticated) {
		redirectTarget := r.URL.String()
		path := src.GetPath(r)

		loginUrl := url.LoginRelative(path, redirectTarget)
		fields := logrus.Fields{
			"redirect_after_login": redirectTarget,
			"redirect_to":          loginUrl,
		}

		logger.WithFields(fields).Info("default: unauthenticated: request matches auto-login; redirecting to login...")
		http.Redirect(w, r, loginUrl, http.StatusSeeOther)
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
