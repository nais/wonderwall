package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

type SessionRefreshSource interface {
	GetSessions() *session.Handler
}

func SessionRefresh(src SessionRefreshSource, w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	key, err := src.GetSessions().GetKey(r)
	if err != nil {
		logger.Infof("session/refresh: getting key: %+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data, err := src.GetSessions().Get(r, key)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrInvalidSession), errors.Is(err, session.ErrKeyNotFound):
			logger.Infof("session/refresh: getting session: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			logger.Warnf("session/refresh: getting session: %+v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	data, err = src.GetSessions().Refresh(r, key, data)
	if err != nil {
		if errors.Is(err, session.ErrInvalidIdpState) || errors.Is(err, session.ErrInvalidSession) {
			logger.Infof("session/refresh: refreshing: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

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
