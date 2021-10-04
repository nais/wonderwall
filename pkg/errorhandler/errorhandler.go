package errorhandler

import (
	"errors"
	"github.com/nais/wonderwall/pkg/middleware/correlationid"
	log "github.com/sirupsen/logrus"
	"net/http"
)

var (
	InvalidSecurityLevelError = errors.New("InvalidSecurityLevel")
	InvalidLocaleError        = errors.New("InvalidLocale")
)

func respondError(w http.ResponseWriter, r *http.Request, statusCode int, cause error) {
	id, ok := correlationid.GetFromContext(r.Context())
	if !ok {
		log.Warnf("no correlation id in context")
	}

	logFields := log.Fields{
		"correlation_id": id,
	}

	log.WithFields(logFields).Error(cause)
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
