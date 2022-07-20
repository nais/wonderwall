package handler

import (
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"

	logentry "github.com/nais/wonderwall/pkg/middleware"
	urlpkg "github.com/nais/wonderwall/pkg/url"
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
	logger := logentry.LogEntry(r)
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
		RetryURI:      urlpkg.Retry(r, h.Config.Ingress, loginCookie),
	}
	err = errorTemplate.Execute(w, errorPage)
	if err != nil {
		logentry.LogEntry(r).Errorf("executing error template: %+v", err)
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
