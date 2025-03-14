package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nais/wonderwall/internal/o11y/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"

	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/pkg/cookie"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/paths"
	urlpkg "github.com/nais/wonderwall/pkg/url"
	"github.com/nais/wonderwall/templates"
)

const (
	// MaxAutoRetryAttempts is the maximum number of times to automatically redirect the user to retry their original request.
	MaxAutoRetryAttempts = 3
)

func (s *Standalone) InternalError(w http.ResponseWriter, r *http.Request, cause error) {
	span := trace.SpanFromContext(r.Context())
	otel.AddErrorEvent(span, "errorHandler", "InternalError", cause)
	s.respondError(w, r, http.StatusInternalServerError, cause, log.ErrorLevel)
}

func (s *Standalone) BadRequest(w http.ResponseWriter, r *http.Request, cause error) {
	span := trace.SpanFromContext(r.Context())
	otel.AddErrorEvent(span, "errorHandler", "BadRequest", cause)
	s.respondError(w, r, http.StatusBadRequest, cause, log.ErrorLevel)
}

func (s *Standalone) Unauthorized(w http.ResponseWriter, r *http.Request, cause error) {
	span := trace.SpanFromContext(r.Context())
	otel.AddErrorEvent(span, "errorHandler", "Unauthorized", cause)
	s.respondError(w, r, http.StatusUnauthorized, cause, log.WarnLevel)
}

func (s *Standalone) TooManyRequests(w http.ResponseWriter, r *http.Request, cause error) {
	span := trace.SpanFromContext(r.Context())
	otel.AddErrorEvent(span, "errorHandler", "TooManyRequests", cause)
	s.respondError(w, r, http.StatusTooManyRequests, cause, log.WarnLevel)
}

// Retry returns a URI that should retry the desired route that failed.
// It only handles the routes exposed by Wonderwall, i.e. `/oauth2/*`. As these routes
// are related to the authentication flow, we default to redirecting back to the handled
// `/oauth2/login` endpoint unless the original request attempted to reach the logout-flow.
func (s *Standalone) Retry(r *http.Request, loginCookie *openid.LoginCookie) string {
	requestPath := r.URL.Path
	ingressPath := s.GetPath(r)

	// redirect failed logout callbacks to logout
	if strings.HasSuffix(requestPath, paths.OAuth2+paths.LogoutCallback) {
		return ingressPath + paths.OAuth2 + paths.Logout
	}

	// redirect failed login callbacks to login with original referer as the redirect_uri
	if strings.HasSuffix(requestPath, paths.OAuth2+paths.LoginCallback) {
		redirect := s.Redirect.Canonical(r)
		if loginCookie != nil && len(loginCookie.Referer) > 0 {
			redirect = s.Redirect.Clean(r, loginCookie.Referer)
		}

		return urlpkg.LoginRelative(ingressPath, redirect)
	}

	u := *r.URL
	u.Host = ""
	u.Scheme = ""
	return u.String()
}

func (s *Standalone) respondError(w http.ResponseWriter, r *http.Request, statusCode int, cause error, level log.Level) {
	span := trace.SpanFromContext(r.Context())
	logger := mw.LogEntryFrom(r).WithFields(httpinternal.Attributes(r))
	msg := "error in route: %+v"

	incrementRetryAttempt(w, r, s.GetCookieOptions(r))

	attempts, ok := getRetryAttempts(r)
	span.SetAttributes(attribute.Int("error.retry_count", attempts))
	if (!ok || attempts < MaxAutoRetryAttempts) && (statusCode != http.StatusTooManyRequests) {
		span.SetAttributes(attribute.Bool("error.retry", true))
		loginCookie, err := openid.GetLoginCookie(r, s.Crypter)
		if err != nil {
			loginCookie = nil
		}

		retryUri := s.Retry(r, loginCookie)
		logger.Infof(msg, cause)
		logger.Infof("errorhandler: auto-retry (attempt %d/%d) redirecting to %q...", attempts+1, MaxAutoRetryAttempts, retryUri)
		http.Redirect(w, r, retryUri, http.StatusTemporaryRedirect)

		return
	}

	if level == log.WarnLevel || errors.Is(cause, context.Canceled) {
		logger.Warnf(msg, cause)
	} else {
		logger.Errorf(msg, cause)
	}

	logger.Infof("errorhandler: maximum retry attempts exceeded; executing error template...")
	span.SetAttributes(attribute.Bool("error.retries_exhausted", true))
	s.defaultErrorResponse(w, r, statusCode)
}

func (s *Standalone) defaultErrorResponse(w http.ResponseWriter, r *http.Request, statusCode int) {
	w.WriteHeader(statusCode)

	loginCookie, err := openid.GetLoginCookie(r, s.Crypter)
	if err != nil {
		loginCookie = nil
	}

	defaultRedirect := s.Ingresses.Single().String()
	if s.Config.SSO.IsServer() {
		defaultRedirect = s.Config.SSO.ServerDefaultRedirectURL
	}

	err = templates.ExecError(w, templates.ErrorVariables{
		CorrelationID:      middleware.GetReqID(r.Context()),
		CSS:                templates.CSS,
		DefaultRedirectURI: defaultRedirect,
		HttpStatusCode:     statusCode,
		RetryURI:           s.Retry(r, loginCookie),
	})
	if err != nil {
		mw.LogEntryFrom(r).Errorf("errorhandler: executing error template: %+v", err)
	}
}

func getRetryAttempts(r *http.Request) (int, bool) {
	c, err := cookie.Get(r, cookie.Retry)
	if err != nil {
		return 0, false
	}

	val, err := strconv.Atoi(c.Value)
	if err != nil {
		return 0, false
	}

	return val, true
}

func incrementRetryAttempt(w http.ResponseWriter, r *http.Request, opts cookie.Options) {
	val := 1

	prev, ok := getRetryAttempts(r)
	if ok {
		val = prev + 1
	}

	c := cookie.Make(cookie.Retry, strconv.Itoa(val), opts)
	cookie.Set(w, c)
}
