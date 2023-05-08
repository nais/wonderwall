package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/handler/templates"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/paths"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

const (
	// MaxAutoRetryAttempts is the maximum number of times to automatically redirect the user to retry their original request.
	MaxAutoRetryAttempts = 3
)

type Page struct {
	CorrelationID string
	RetryURI      string
}

func (s *Standalone) InternalError(w http.ResponseWriter, r *http.Request, cause error) {
	s.respondError(w, r, http.StatusInternalServerError, cause, log.ErrorLevel)
}

func (s *Standalone) BadRequest(w http.ResponseWriter, r *http.Request, cause error) {
	s.respondError(w, r, http.StatusBadRequest, cause, log.ErrorLevel)
}

func (s *Standalone) Unauthorized(w http.ResponseWriter, r *http.Request, cause error) {
	s.respondError(w, r, http.StatusUnauthorized, cause, log.WarnLevel)
}

// Retry returns a URI that should retry the desired route that failed.
// It only handles the routes exposed by Wonderwall, i.e. `/oauth2/*`. As these routes
// are related to the authentication flow, we default to redirecting back to the handled
// `/oauth2/login` endpoint unless the original request attempted to reach the logout-flow.
func (s *Standalone) Retry(r *http.Request, loginCookie *openid.LoginCookie) string {
	requestPath := r.URL.Path
	ingressPath := s.GetPath(r)

	for _, path := range []string{paths.Logout, paths.LogoutLocal, paths.LogoutFrontChannel} {
		if strings.HasSuffix(requestPath, paths.OAuth2+path) {
			return requestPath
		}
	}

	redirect := s.Redirect.Canonical(r)
	if loginCookie != nil && len(loginCookie.Referer) > 0 {
		redirect = s.Redirect.Clean(r, loginCookie.Referer)
	}

	return urlpkg.LoginRelative(ingressPath, redirect)
}

func (s *Standalone) respondError(w http.ResponseWriter, r *http.Request, statusCode int, cause error, level log.Level) {
	logger := mw.LogEntryFrom(r)
	msg := "error in route: %+v"

	incrementRetryAttempt(w, r, s.GetCookieOptions(r))

	attempts, ok := getRetryAttempts(r)
	if !ok || ok && attempts < MaxAutoRetryAttempts {
		loginCookie, err := openid.GetLoginCookie(r, s.Crypter)
		if err != nil {
			loginCookie = nil
		}

		retryUri := s.Retry(r, loginCookie)
		logger.Debugf(msg, cause)
		logger.Debugf("errorhandler: auto-retry (attempt %d/%d) redirecting to %q...", attempts+1, MaxAutoRetryAttempts, retryUri)
		http.Redirect(w, r, retryUri, http.StatusTemporaryRedirect)

		return
	}

	if level == log.WarnLevel || errors.Is(cause, context.Canceled) {
		logger.Warnf(msg, cause)
	} else {
		logger.Errorf(msg, cause)
	}

	logger.Debugf("errorhandler: maximum retry attempts exceeded; executing error template...")
	s.defaultErrorResponse(w, r, statusCode)
}

func (s *Standalone) defaultErrorResponse(w http.ResponseWriter, r *http.Request, statusCode int) {
	w.WriteHeader(statusCode)

	loginCookie, err := openid.GetLoginCookie(r, s.Crypter)
	if err != nil {
		loginCookie = nil
	}

	errorPage := Page{
		CorrelationID: middleware.GetReqID(r.Context()),
		RetryURI:      s.Retry(r, loginCookie),
	}
	err = templates.ErrorTemplate.Execute(w, errorPage)
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
	c.UnsetExpiry()
	cookie.Set(w, c)
}
