package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	urllib "net/url"
	"slices"
	"sync"

	"github.com/nais/wonderwall/internal/dpop"
	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/pkg/handler/acr"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
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
	enableAccessLogs          bool
	includeIDToken            bool
	preserveInboundHostHeader bool
	dpop                      *upstreamDPoP
}

type ReverseProxyOption func(*ReverseProxy)

func WithDPoPProof(proofer DPoPProofer) ReverseProxyOption {
	return func(rp *ReverseProxy) {
		rp.dpop = &upstreamDPoP{proofer: proofer}
	}
}

func WithAccessLogs(enabled bool) ReverseProxyOption {
	return func(rp *ReverseProxy) {
		rp.enableAccessLogs = enabled
	}
}

func WithIDToken(enabled bool) ReverseProxyOption {
	return func(rp *ReverseProxy) {
		rp.includeIDToken = enabled
	}
}

func WithPreserveInboundHostHeader() ReverseProxyOption {
	return func(rp *ReverseProxy) {
		rp.preserveInboundHostHeader = true
	}
}

func NewUpstreamProxy(upstream *urllib.URL, opts ...ReverseProxyOption) *ReverseProxy {
	opts = append(opts, WithPreserveInboundHostHeader())
	return NewReverseProxy(upstream, opts...)
}

func NewReverseProxy(upstream *urllib.URL, opts ...ReverseProxyOption) *ReverseProxy {
	rp := &ReverseProxy{}
	for _, opt := range opts {
		opt(rp)
	}

	rp.ReverseProxy = &httputil.ReverseProxy{
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
			r.SetURL(upstream)

			// preserve inbound Forwarded and X-Forwarded-* headers that is stripped when using Rewrite
			// this presumes that we're behind a trusted reverse proxy (e.g. gateway or ingress controller)
			for _, header := range []string{
				"Forwarded",
				"X-Forwarded-For",
				"X-Forwarded-Host",
				"X-Forwarded-Proto",
			} {
				if values := r.In.Header.Values(header); len(values) > 0 {
					r.Out.Header[header] = slices.Clone(values)
				}
			}

			if rp.preserveInboundHostHeader {
				// preserve the inbound request's Host header
				r.Out.Host = r.In.Host
			}

			accessToken, ok := mw.AccessTokenFrom(r.In.Context())
			if ok {
				// A valid session replaces caller credentials. Remove any caller DPoP proof before setting session credentials.
				r.Out.Header.Del("DPoP")

				tokenType := openid.TokenTypeBearer
				if proof, exists := mw.DPoPProofFrom(r.In.Context()); exists {
					tokenType = openid.TokenTypeDPoP
					r.Out.Header.Set("DPoP", proof)
				}

				r.Out.Header.Set("Authorization", tokenType+" "+accessToken)
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
		ModifyResponse: func(response *http.Response) error {
			if response.Request == nil {
				return nil
			}
			if _, ok := mw.DPoPProofFrom(response.Request.Context()); !ok || rp.dpop == nil {
				return nil
			}
			rp.dpop.captureNonce(response.Header.Get("DPoP-Nonce"))
			return nil
		},
	}
	return rp
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

		if rp.dpop != nil {
			proof, proofErr := rp.dpop.proof(r, accessToken)
			if proofErr != nil {
				logger.WithError(proofErr).Error("reverseproxy: failed to create DPoP proof")
				otel.AddErrorEvent(span, "dpopProofError", "proof", proofErr)
				http.Error(w, "failed to create DPoP proof", http.StatusInternalServerError)
				return
			}

			ctx = mw.WithDPoPProof(ctx, proof)
			span.SetAttributes(attribute.Bool("proxy.with_dpop", true))
		}

		span.SetAttributes(attribute.Bool("proxy.with_access_token", true))
		if rp.includeIDToken && sess != nil {
			ctx = mw.WithIDToken(ctx, sess.IDToken())
			span.SetAttributes(attribute.Bool("proxy.with_id_token", true))
		}

		if rp.enableAccessLogs && isRelevantAccessLog(r) {
			logger.Info("default: authenticated request")
		}
	}

	ctx, span = otel.StartSpan(ctx, "ReverseProxy.ServeHTTP")
	defer span.End()
	rp.ServeHTTP(w, r.WithContext(ctx))
}

// DPoPProofer constructs a DPoP proof.
type DPoPProofer func(ctx context.Context, method string, target *urllib.URL, nonce, accessToken string) (string, error)

type upstreamDPoP struct {
	proofer DPoPProofer
	nonceMu sync.RWMutex
	nonce   string
}

func (d *upstreamDPoP) proof(r *http.Request, accessToken string) (string, error) {
	ingressURL, err := url.MatchingIngress(r)
	if err != nil {
		return "", err
	}
	target := dpop.TargetURI(ingressURL, r)
	return d.proofer(r.Context(), r.Method, target, d.nonceValue(), accessToken)
}

func (d *upstreamDPoP) captureNonce(nonce string) {
	if nonce == "" {
		return
	}
	d.nonceMu.Lock()
	d.nonce = nonce
	d.nonceMu.Unlock()
}

func (d *upstreamDPoP) nonceValue() string {
	d.nonceMu.RLock()
	defer d.nonceMu.RUnlock()
	return d.nonce
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
		// #nosec G710 -- the location is a relative URL; the redirect target within it is validated by the login handler
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
		_, _ = w.Write([]byte(`{"error": "unauthenticated, please log in"}`))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthenticated, please log in"))
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
