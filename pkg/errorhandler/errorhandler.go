package errorhandler

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"net/http"
)

var (
	InvalidSecurityLevelError = errors.New("InvalidSecurityLevel")
	InvalidLocaleError        = errors.New("InvalidLocale")
)

func respondError(w http.ResponseWriter, statusCode int, cause error) {
	log.Error(cause)
	w.WriteHeader(statusCode)
}

func InternalError(w http.ResponseWriter, cause error) {
	respondError(w, http.StatusInternalServerError, cause)
}

func BadRequest(w http.ResponseWriter, cause error) {
	respondError(w, http.StatusBadRequest, cause)
}

func Unauthorized(w http.ResponseWriter, cause error) {
	respondError(w, http.StatusUnauthorized, cause)
}
