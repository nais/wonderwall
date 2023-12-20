package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	urllib "net/url"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/handler/acr"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/server"
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
}

func NewUpstreamProxy(upstream *urllib.URL, enableAccessLogs bool) *ReverseProxy {
	rp := NewReverseProxy(upstream, true)
	rp.EnableAccessLogs = enableAccessLogs
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

			r.Out.Header.Del("X-Wonderwall-Acr")
			r.Out.Header.Del("X-Wonderwall-Amr")
			r.Out.Header.Del("X-Wonderwall-Auth-Time")
			r.Out.Header.Del("X-Wonderwall-Sid")

			sessAcr, ok := mw.AcrFrom(r.In.Context())
			if ok && sessAcr != "" {
				r.Out.Header.Set("X-Wonderwall-Acr", sessAcr)
			}

			amr, ok := mw.AmrFrom(r.In.Context())
			if ok && amr != "" {
				r.Out.Header.Set("X-Wonderwall-Amr", amr)
			}

			authTime, ok := mw.AuthTimeFrom(r.In.Context())
			if ok && authTime != "" {
				r.Out.Header.Set("X-Wonderwall-Auth-Time", authTime)
			}

			sid, ok := mw.SessionIDFrom(r.In.Context())
			if ok && sid != "" {
				r.Out.Header.Set("X-Wonderwall-Sid", sid)
			}
		},
		Transport: server.DefaultTransport(),
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
		if sessAcr := sess.Acr(); sessAcr != "" {
			ctx = mw.WithAcr(ctx, sessAcr)
		}

		if amr := sess.Amr(); amr != "" {
			ctx = mw.WithAmr(ctx, amr)
		}

		if authTime := sess.AuthTime(); authTime != "" {
			ctx = mw.WithAuthTime(ctx, authTime)
		}

		if sid := sess.ExternalSessionID(); sid != "" {
			logger = logger.WithField("sid", sid)
			ctx = mw.WithSessionID(ctx, sid)
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

		if rp.EnableAccessLogs {
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

	if isNavigationRequest(r) {
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

	if accepts(r, "*/*", "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error": "unauthenticated, please log in"}`))
	} else {
		w.Write([]byte("unauthenticated, please log in"))
	}
}

func isNavigationRequest(r *http.Request) bool {
	// we assume that navigation requests are always GET requests
	if r.Method != http.MethodGet {
		return false
	}

	// check for top-level navigation requests
	mode := r.Header.Get("Sec-Fetch-Mode")
	dest := r.Header.Get("Sec-Fetch-Dest")
	if mode != "" && dest != "" {
		return mode == "navigate" && dest == "document"
	}

	// fallback if browser doesn't support fetch metadata
	return accepts(r, "text/html")
}

func accepts(r *http.Request, accepted ...string) bool {
	// iterate over all Accept headers
	for _, header := range r.Header.Values("Accept") {
		// iterate over all comma-separated values in a single Accept header
		for _, v := range strings.Split(header, ",") {
			v = strings.ToLower(v)
			v = strings.TrimSpace(v)
			v = strings.Split(v, ";")[0]

			for _, accept := range accepted {
				if v == accept {
					return true
				}
			}
		}
	}

	return false
}

type logrusErrorWriter struct{}

func (w logrusErrorWriter) Write(p []byte) (n int, err error) {
	logrus.Warnf("%s", string(p))
	return len(p), nil
}
