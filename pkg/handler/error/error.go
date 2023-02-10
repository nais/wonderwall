package error

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler/templates"
	urlpkg "github.com/nais/wonderwall/pkg/handler/url"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/paths"
)

const (
	// MaxAutoRetryAttempts is the maximum number of times to automatically redirect the user to retry their original request.
	MaxAutoRetryAttempts = 3
)

type Source interface {
	GetCookieOptsPathAware(r *http.Request) cookie.Options
	GetCrypter() crypto.Crypter
	GetErrorPath() string
	GetPath(r *http.Request) string
}

type Page struct {
	CorrelationID string
	RetryURI      string
}

type Handler struct {
	Source
}

func New(src Source) Handler {
	return Handler{src}
}

func (h Handler) InternalError(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusInternalServerError, cause, log.ErrorLevel)
}

func (h Handler) BadRequest(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusBadRequest, cause, log.ErrorLevel)
}

func (h Handler) Unauthorized(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusUnauthorized, cause, log.WarnLevel)
}

// Retry returns a URI that should retry the desired route that failed.
// It only handles the routes exposed by Wonderwall, i.e. `/oauth2/*`. As these routes
// are related to the authentication flow, we default to redirecting back to the handled
// `/oauth2/login` endpoint unless the original request attempted to reach the logout-flow.
func (h Handler) Retry(r *http.Request, loginCookie *openid.LoginCookie) string {
	requestPath := r.URL.Path
	ingressPath := h.GetPath(r)

	if strings.HasSuffix(requestPath, paths.OAuth2+paths.Logout) || strings.HasSuffix(requestPath, paths.OAuth2+paths.LogoutFrontChannel) {
		return requestPath
	}

	redirect := urlpkg.CanonicalRedirect(r)

	if loginCookie != nil && len(loginCookie.Referer) > 0 {
		redirect = loginCookie.Referer
	}

	return urlpkg.LoginURL(ingressPath, redirect)
}

func (h Handler) respondError(w http.ResponseWriter, r *http.Request, statusCode int, cause error, level log.Level) {
	logger := mw.LogEntryFrom(r)
	msg := "error in route: %+v"

	incrementRetryAttempt(w, r, h.GetCookieOptsPathAware(r))

	attempts, ok := getRetryAttempts(r)
	if !ok || ok && attempts < MaxAutoRetryAttempts {
		loginCookie, err := openid.GetLoginCookie(r, h.GetCrypter())
		if err != nil {
			loginCookie = nil
		}

		retryUri := h.Retry(r, loginCookie)
		logger.Warnf(msg, cause)

		logger.Infof("errorhandler: auto-retry (attempt %d/%d) redirecting to %q...", attempts+1, MaxAutoRetryAttempts, retryUri)
		http.Redirect(w, r, retryUri, http.StatusTemporaryRedirect)

		return
	}

	if level == log.WarnLevel || errors.Is(cause, context.Canceled) {
		logger.Warnf(msg, cause)
	} else {
		logger.Errorf(msg, cause)
	}

	logger.Info("errorhandler: maximum retry attempts exceeded; executing error template...")

	if len(h.GetErrorPath()) > 0 {
		err := h.customErrorRedirect(w, r, statusCode)
		if err == nil {
			return
		}
	}

	h.defaultErrorResponse(w, r, statusCode)
}

func (h Handler) defaultErrorResponse(w http.ResponseWriter, r *http.Request, statusCode int) {
	w.WriteHeader(statusCode)

	loginCookie, err := openid.GetLoginCookie(r, h.GetCrypter())
	if err != nil {
		loginCookie = nil
	}

	errorPage := Page{
		CorrelationID: middleware.GetReqID(r.Context()),
		RetryURI:      h.Retry(r, loginCookie),
	}
	err = templates.ErrorTemplate.Execute(w, errorPage)
	if err != nil {
		mw.LogEntryFrom(r).Errorf("errorhandler: executing error template: %+v", err)
	}
}

func (h Handler) customErrorRedirect(w http.ResponseWriter, r *http.Request, statusCode int) error {
	override, err := url.ParseRequestURI(h.GetErrorPath())
	if err != nil {
		return err
	}

	// strip scheme and host to avoid cross-domain redirects
	override.Scheme = ""
	override.Host = ""

	query := override.Query()
	query.Add("correlation_id", middleware.GetReqID(r.Context()))
	query.Add("status_code", strconv.Itoa(statusCode))

	override.RawQuery = query.Encode()

	errorRedirectURI := override.String()
	http.Redirect(w, r, errorRedirectURI, http.StatusFound)
	return nil
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
