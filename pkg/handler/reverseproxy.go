package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	urllib "net/url"

	"github.com/sirupsen/logrus"

	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/pkg/handler/acr"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/url"
)

type ReverseProxySource interface {
	GetAcrHandler() *acr.Handler
	GetAutoLogin() *autologin.AutoLogin
	GetPath(r *http.Request) string
	GetSession(r *http.Request) (*session.Session, error)
}

type ReverseProxy struct {
	*httputil.ReverseProxy
	EnableAccessLogs bool
	IncludeIdToken   bool
}

func NewUpstreamProxy(upstream *urllib.URL, enableAccessLogs bool, includeIdToken bool) *ReverseProxy {
	rp := NewReverseProxy(upstream, true)
	rp.EnableAccessLogs = enableAccessLogs
	rp.IncludeIdToken = includeIdToken
	return rp
}

func NewReverseProxy(upstream *urllib.URL, preserveInboundHostHeader bool) *ReverseProxy {
	rp := &httputil.ReverseProxy{
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
		Rewrite: func(r *httputil.ProxyRequest) {
			// preserve inbound Forwarded and X-Forwarded-* headers that is stripped when using Rewrite
			// this presumes that we're behind a trusted reverse proxy (e.g. gateway or ingress controller)
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

			idToken, ok := mw.IdTokenFrom(r.In.Context())
			if ok {
				r.Out.Header.Set("X-Wonderwall-Id-Token", idToken)
			}
		},
		Transport: httpinternal.Transport(),
	}
	return &ReverseProxy{
		ReverseProxy: rp,
	}
}

func (rp *ReverseProxy) Handler(src ReverseProxySource, w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)
	isAuthenticated := false

	sess, accessToken, err := getSessionWithValidToken(src, r)
	switch {
	case err == nil:
		// add authentication if session checks out
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

	ctx := r.Context()
	if sess != nil {
		if sid := sess.ExternalSessionID(); sid != "" {
			logger = logger.WithField("sid", sid)
		}
	}

	err = src.GetAcrHandler().Validate(sess)
	if err != nil {
		isAuthenticated = false
		logger.Infof("default: unauthenticated: acr: %+v; checking for autologin...", err)
	}

	if src.GetAutoLogin().NeedsLogin(r, isAuthenticated) {
		handleAutologin(src, w, r, logger)
		return
	}

	if isAuthenticated {
		ctx = mw.WithAccessToken(ctx, accessToken)
		if rp.IncludeIdToken && sess != nil {
			idToken := sess.IDToken()
			ctx = mw.WithIdToken(ctx, idToken)
		}

		if rp.EnableAccessLogs && isRelevantAccessLog(r) {
			logger.Info("default: authenticated request")
		}
	}

	rp.ServeHTTP(w, r.WithContext(ctx))
}

func getSessionWithValidToken(src ReverseProxySource, r *http.Request) (*session.Session, string, error) {
	sess, err := src.GetSession(r)
	if err != nil {
		return nil, "", err
	}

	accessToken, err := sess.AccessToken()
	if err != nil {
		return nil, "", err
	}

	return sess, accessToken, nil
}

func handleAutologin(src ReverseProxySource, w http.ResponseWriter, r *http.Request, logger *logrus.Entry) {
	path := src.GetPath(r)

	loginURL := func(redirectTarget, message string) string {
		// we don't validate/clean the redirect target as this is done by the login handler anyway
		loginURL := url.LoginRelative(path, redirectTarget)

		logger.WithFields(logrus.Fields{
			"redirect_after_login": redirectTarget,
			"login_url":            loginURL,
		}).Infof("default: unauthenticated: autologin: %s", message)

		return loginURL
	}

	if httpinternal.IsNavigationRequest(r) {
		target := r.URL.String()
		location := loginURL(target, "navigation request detected; redirecting to login...")
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	// not a navigation request, so we can't respond with 3xx to redirect
	target := r.Referer()
	if target == "" {
		target = path
	}

	location := loginURL(target, "non-navigation request detected; responding with 401 and Location header")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusUnauthorized)

	if httpinternal.Accepts(r, "*/*", "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error": "unauthenticated, please log in"}`))
	} else {
		w.Write([]byte("unauthenticated, please log in"))
	}
}

func isRelevantAccessLog(r *http.Request) bool {
	if r.Method == http.MethodGet {
		// only log GET requests that are navigation requests
		return httpinternal.IsNavigationRequest(r)
	}

	// all other methods are relevant
	return true
}

type logrusErrorWriter struct{}

func (w logrusErrorWriter) Write(p []byte) (n int, err error) {
	logrus.Warnf("%s", string(p))
	return len(p), nil
}
