package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	urllib "net/url"

	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/pkg/handler/acr"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/url"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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
	IncludeIDToken   bool
}

func NewUpstreamProxy(upstream *urllib.URL, enableAccessLogs bool, includeIDToken bool) *ReverseProxy {
	rp := NewReverseProxy(upstream, true)
	rp.EnableAccessLogs = enableAccessLogs
	rp.IncludeIDToken = includeIDToken
	return rp
}

func NewReverseProxy(upstream *urllib.URL, preserveInboundHostHeader bool) *ReverseProxy {
	rp := &httputil.ReverseProxy{
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger := mw.LogEntryFrom(r).WithFields(httpinternal.Attributes(r))

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

			idToken, ok := mw.IDTokenFrom(r.In.Context())
			if ok {
				r.Out.Header.Set("X-Wonderwall-Id-Token", idToken)
			} else {
				// remove the header if it was set by the client
				r.Out.Header.Del("X-Wonderwall-Id-Token")
			}
		},
		Transport: httpinternal.Transport(),
	}
	return &ReverseProxy{
		ReverseProxy: rp,
	}
}

func (rp *ReverseProxy) Handler(src ReverseProxySource, w http.ResponseWriter, r *http.Request) {
	r, span := otel.StartSpanFromRequest(r, "ReverseProxy")
	defer span.End()

	logger := mw.LogEntryFrom(r).WithFields(httpinternal.Attributes(r))

	unauthenticatedEvent := func(level logrus.Level, errType string, err error) {
		logger.WithError(err).Logf(level, "unauthenticated: %+v", err)
		otel.AddErrorEvent(span, "unauthenticated", errType, err)
	}

	isAuthenticated := false
	sess, accessToken, err := getSessionWithValidToken(src, r)
	switch {
	case err == nil:
		// add authentication if session checks out
		isAuthenticated = true
	case errors.Is(err, context.Canceled):
		unauthenticatedEvent(logrus.DebugLevel, "context.Canceled", fmt.Errorf("client disconnected before we could respond: %w", err))
	case errors.Is(err, session.ErrInvalidExternal):
		unauthenticatedEvent(logrus.WarnLevel, "session.ErrInvalidExternal", err)
	case errors.Is(err, session.ErrNotFound):
		unauthenticatedEvent(logrus.DebugLevel, "session.ErrNotFound", err)
	case errors.Is(err, session.ErrInvalid):
		unauthenticatedEvent(logrus.InfoLevel, "session.ErrInvalid", err)
	default:
		unauthenticatedEvent(logrus.ErrorLevel, "unexpected", fmt.Errorf("unexpected error: %w", err))
		span.SetStatus(codes.Error, err.Error())
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

	span.SetAttributes(attribute.Bool("session.authenticated", isAuthenticated))

	if src.GetAutoLogin().NeedsLogin(r, isAuthenticated) {
		span.SetAttributes(attribute.Bool("proxy.needs_autologin", true))
		handleAutologin(src, w, r, logger)
		return
	}

	if isAuthenticated {
		ctx = mw.WithAccessToken(ctx, accessToken)
		span.SetAttributes(attribute.Bool("proxy.with_access_token", true))
		if rp.IncludeIDToken && sess != nil {
			ctx = mw.WithIDToken(ctx, sess.IDToken())
			span.SetAttributes(attribute.Bool("proxy.with_id_token", true))
		}

		if rp.EnableAccessLogs && isRelevantAccessLog(r) {
			logger.Info("default: authenticated request")
		}
	}

	ctx, span = otel.StartSpan(ctx, "ReverseProxy.ServeHTTP")
	defer span.End()
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
	span := trace.SpanFromContext(r.Context())
	path := src.GetPath(r)

	loginURL := func(redirectTarget, message string) string {
		// we don't validate/clean the redirect target as this is done by the login handler anyway
		loginURL := url.LoginRelative(path, redirectTarget)

		logger.WithFields(logrus.Fields{
			"redirect_after_login": redirectTarget,
			"login_url":            loginURL,
		}).Infof("default: unauthenticated: autologin: %s", message)
		span.SetAttributes(attribute.String("autologin.redirect_after", redirectTarget))
		span.SetAttributes(attribute.String("autologin.login_url", loginURL))

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

	if httpinternal.Accepts(r, "*/*", "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthenticated, please log in"}`))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
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
