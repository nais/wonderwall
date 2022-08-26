package handler

import (
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"

	urlpkg "github.com/nais/wonderwall/pkg/handler/url"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/paths"
)

type ErrorPage struct {
	CorrelationID string
	RetryURI      string
}

//go:embed templates/error.gohtml
var errorGoHtml string
var errorTemplate *template.Template

func init() {
	var err error

	errorTemplate = template.New("error")
	errorTemplate, err = errorTemplate.Parse(errorGoHtml)
	if err != nil {
		log.Fatalf("parsing error template: %+v", err)
	}
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, statusCode int, cause error, level log.Level) {
	logger := mw.LogEntryFrom(r)
	msg := "error in route: %+v"

	switch level {
	case log.WarnLevel:
		logger.Warnf(msg, cause)
	default:
		logger.Errorf(msg, cause)
	}

	if len(h.Config.ErrorRedirectURI) > 0 {
		err := h.customErrorRedirect(w, r, statusCode)
		if err == nil {
			return
		}
	}

	h.defaultErrorResponse(w, r, statusCode)
}

func (h *Handler) defaultErrorResponse(w http.ResponseWriter, r *http.Request, statusCode int) {
	w.WriteHeader(statusCode)

	loginCookie, err := h.getLoginCookie(r)
	if err != nil {
		loginCookie = nil
	}

	errorPage := ErrorPage{
		CorrelationID: middleware.GetReqID(r.Context()),
		RetryURI:      h.Retry(r, loginCookie),
	}
	err = errorTemplate.Execute(w, errorPage)
	if err != nil {
		mw.LogEntryFrom(r).Errorf("executing error template: %+v", err)
	}
}

func (h *Handler) customErrorRedirect(w http.ResponseWriter, r *http.Request, statusCode int) error {
	override, err := url.Parse(h.Config.ErrorRedirectURI)
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

func (h *Handler) InternalError(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusInternalServerError, cause, log.ErrorLevel)
}

func (h *Handler) BadRequest(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusBadRequest, cause, log.ErrorLevel)
}

func (h *Handler) Unauthorized(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusUnauthorized, cause, log.WarnLevel)
}

// Retry returns a URI that should retry the desired route that failed.
// It only handles the routes exposed by Wonderwall, i.e. `/oauth2/*`. As these routes
// are related to the authentication flow, we default to redirecting back to the handled
// `/oauth2/login` endpoint unless the original request attempted to reach the logout-flow.
func (h *Handler) Retry(r *http.Request, loginCookie *openid.LoginCookie) string {
	requestPath := r.URL.Path
	ingressPath := h.Path(r)

	if strings.HasSuffix(requestPath, paths.OAuth2+paths.Logout) || strings.HasSuffix(requestPath, paths.OAuth2+paths.FrontChannelLogout) {
		return requestPath
	}

	redirect := urlpkg.CanonicalRedirect(r)

	if loginCookie != nil && len(loginCookie.Referer) > 0 {
		redirect = loginCookie.Referer
	}

	return urlpkg.LoginURL(ingressPath, redirect)
}
