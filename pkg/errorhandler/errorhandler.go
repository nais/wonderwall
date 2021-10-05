package errorhandler

import (
	"net/http"

	"github.com/go-chi/httplog"
)

func respondError(w http.ResponseWriter, r *http.Request, statusCode int, cause error) {
	logger := httplog.LogEntry(r.Context())
	logger.Error().Stack().Err(cause).Msgf("error in route: %+v", cause)
	w.WriteHeader(statusCode)
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
