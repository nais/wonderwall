package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	urllib "net/url"

	"github.com/sirupsen/logrus"

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
}

func NewReverseProxy(upstream *urllib.URL, preserveInboundHostHeader bool) *ReverseProxy {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 200
	t.MaxIdleConnsPerHost = 100

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
		},
		Transport: t,
	}
	return &ReverseProxy{rp}
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

	err = src.GetAcrHandler().Validate(sess)
	if err != nil {
		isAuthenticated = false
		logger.Infof("default: unauthenticated: acr: %+v; checking for autologin...", err)
	}

	if src.GetAutoLogin().NeedsLogin(r, isAuthenticated) {
		loginRedirect(src, w, r, "request matches autologin")
		return
	}

	ctx := r.Context()

	if isAuthenticated {
		ctx = mw.WithAccessToken(ctx, accessToken)
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

func loginRedirect(src ReverseProxySource, w http.ResponseWriter, r *http.Request, message string) {
	redirectTarget := r.URL.String()
	path := src.GetPath(r)

	loginUrl := url.LoginRelative(path, redirectTarget)
	fields := logrus.Fields{
		"redirect_after_login": redirectTarget,
		"redirect_to":          loginUrl,
	}

	mw.LogEntryFrom(r).WithFields(fields).Infof("default: unauthenticated: %s; redirecting to login...", message)
	http.Redirect(w, r, loginUrl, http.StatusFound)
}

type logrusErrorWriter struct{}

func (w logrusErrorWriter) Write(p []byte) (n int, err error) {
	logrus.Warnf("%s", string(p))
	return len(p), nil
}
