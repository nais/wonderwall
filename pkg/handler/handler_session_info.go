package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

// SessionInfo returns metadata for the current user's session.
func (h *Handler) SessionInfo(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	data, err := h.Sessions.Get(r)
	if err != nil {
		if errors.Is(err, session.CookieNotFoundError) || errors.Is(err, session.KeyNotFoundError) {
			logger.Infof("session/info: getting session: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Warnf("session/info: getting session: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(data.Metadata.Verbose())
	if err != nil {
		logger.Warnf("session/info: marshalling metadata: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
