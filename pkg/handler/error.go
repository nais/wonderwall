package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/handler/templates"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/paths"
	urlpkg "github.com/nais/wonderwall/pkg/url"
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
	logger := mw.LogEntryFrom(r)
	msg := "error in route: %+v"

	if level == log.WarnLevel || errors.Is(cause, context.Canceled) {
		logger.Warnf(msg, cause)
	} else {
		logger.Errorf(msg, cause)
	}

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
		logger.Errorf("errorhandler: executing error template: %+v", err)
	}
}
