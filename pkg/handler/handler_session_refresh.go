package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

// SessionRefresh refreshes current user's session and returns the associated updated metadata.
func (h *Handler) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	if !h.Config.Session.Refresh {
		http.NotFound(w, r)
		return
	}

	logger := mw.LogEntryFrom(r)

	key, err := h.Sessions.GetKey(r)
	if err != nil {
		logger.Infof("session/refresh: getting key: %+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data, err := h.Sessions.Get(r)
	if err != nil {
		if errors.Is(err, session.KeyNotFoundError) {
			logger.Infof("session/refresh: getting session: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Warnf("session/refresh: getting session: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	data, err = h.Sessions.Refresh(r, key, data)
	if err != nil {
		logger.Warnf("session/refresh: refreshing: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(data.Metadata.VerboseWithRefresh())
	if err != nil {
		logger.Warnf("session/refresh: marshalling metadata: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
