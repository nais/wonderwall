package errorhandler

import (
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nais/wonderwall/pkg/request"
	"html/template"
	"net/http"

	"github.com/go-chi/httplog"
)

type ErrorPage struct {
	CorrelationID        string
	CanonicalRedirectURL string
}

func respondError(w http.ResponseWriter, r *http.Request, statusCode int, cause error) {
	logger := httplog.LogEntry(r.Context())
	logger.Error().Stack().Err(cause).Msgf("error in route: %+v", cause)
	w.WriteHeader(statusCode)
	t, _ := template.ParseFiles("templates/error.html")
	errorPage := ErrorPage{
		CorrelationID:        middleware.GetReqID(r.Context()),
		CanonicalRedirectURL: request.CanonicalRedirectURL(r),
	}
	t.Execute(w, errorPage)
}

func InternalError(w http.ResponseWriter, r *http.Request, cause error) {
	respondError(w, r, http.StatusInternalServerError, cause)
}

func BadRequest(w http.ResponseWriter, r *http.Request, cause error) {
	respondError(w, r, http.StatusBadRequest, cause)
}

func Unauthorized(w http.ResponseWriter, r *http.Request, cause error) {
	respondError(w, r, http.StatusUnauthorized, cause)
}
